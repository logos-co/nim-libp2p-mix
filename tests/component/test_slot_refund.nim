# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import libp2p/[protocols/protocol, peerid, switch, builders, varint]
import libp2p_mix
import libp2p_mix/[exit_connection, mix_node, mix_protocol, multiaddr, serialization]
import libp2p_mix/cover_traffic
import libp2p_mix/delay_strategy
import libp2p_mix/spam_protection

import ../tools/[lifecycle, unittest, crypto]
import ../[utils, spam_protection_impl]

const
  TestCodec = "/mix/test/slot-refund/1.0.0"
  ReplyPayload = @[1.byte, 2, 3]

proc setupCountingNodes(
    numNodes: int
): tuple[nodes: seq[MixProtocol], spam: seq[ReclaimCountingSpamProtection]] =
  ## setupMixNodes cannot hand back the spam protection instances, and these
  ## tests need to observe what each node reclaims.
  let nodeInfos = MixNodeInfo.generateRandomMany(numNodes, rng())
  for mixNodeInfo in nodeInfos:
    let
      switch = createSwitch(mixNodeInfo.multiAddr, Opt.some(mixNodeInfo.libp2pPrivKey))
      spam = newReclaimCountingSpamProtection()
      node = MixProtocol.new(
        mixNodeInfo,
        switch,
        spamProtection = Opt.some(SpamProtection(spam)),
        delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
      )
    node.registerDestReadBehavior(TestCodec, readLp(1024))
    switch.mount(node)
    node.nodePool.add(nodeInfos.includeAllExcept(mixNodeInfo))
    result.nodes.add(node)
    result.spam.add(spam)

proc attachCover(node: MixProtocol): ConstantRateCoverTraffic =
  ## Cover is attached after the forward message so that only the packets under
  ## test consume slots. The timer stays off: epochs change when a test says so.
  result = ConstantRateCoverTraffic.new(totalSlots = 4, useInternalEpochTimer = false)
  result.onEpochChange(1)
  node.coverTraffic = Opt.some(CoverTraffic(result))

proc firstHop(nodes: seq[MixProtocol], surb: SURB): MixProtocol =
  let (peerId, _) = surb.hop.get().bytesToMultiAddr().expect("valid SURB hop")
  nodes.filterIt(it.switch.peerInfo.peerId == peerId)[0]

when defined(libp2p_mix_experimental_exit_is_dest):
  proc requestSurb(
      nodes: seq[MixProtocol]
  ): Future[tuple[surb: SURB, conn: Connection]] {.async.} =
    ## Starts the nodes and sends one request from the first node to the last,
    ## returning the SURB that the last node received with it.
    let surbs = newAsyncQueue[SURB]()
    nodes[^1].switch.mount(
      LPProtocol.new(
        codecs = @[TestCodec],
        handler = proc(
            conn: Connection, proto: string
        ) {.async: (raises: [CancelledError]).} =
          try:
            discard await conn.readLp(1024)
            await surbs.put(MixExitConnection(conn).takeSURBs()[0])
          except LPStreamError as exc:
            raiseAssert exc.msg
        ,
      )
    )
    await startNodes(nodes)

    let conn = nodes[0]
      .toConnection(
        MixDestination.exitNode(nodes[^1].switch.peerInfo.peerId),
        TestCodec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
      )
      .expect("could not build connection")
    await conn.writeLp(@[1.byte])
    return (await surbs.get().wait(5.seconds), conn)

  suite "Slot refund - SURB reply":
    asyncTeardown:
      checkTrackers()

    asyncTest "failed first dial refunds the slot and reclaims the proof":
      let (nodes, spam) = setupCountingNodes(10)
      let (surb, conn) = await nodes.requestSurb()
      defer:
        await conn.close()
        await stopNodes(nodes)
      let ct = nodes[^1].attachCover()

      await nodes.firstHop(surb).switch.stop()
      let reclaimedBefore = spam[^1].reclaimCount

      check (await nodes[^1].sendSurbReply(surb, ReplyPayload)).isErr
      check ct.slotPool.nonCoverClaimed == 0
      check spam[^1].reclaimCount == reclaimedBefore + 1

    asyncTest "failure after a write attempt keeps the slot and the proof spent":
      ## The next hop may hold a packet whose write reported an error, so
      ## reissuing its messageId would risk an RLN double-signal.
      let (nodes, spam) = setupCountingNodes(10)
      let (surb, conn) = await nodes.requestSurb()
      defer:
        await conn.close()
        await stopNodes(nodes)
      let ct = nodes[^1].attachCover()

      # A successful reply caches the connection, so the next send writes to it
      check (await nodes[^1].sendSurbReply(surb, ReplyPayload)).isOk
      await nodes.firstHop(surb).switch.stop()
      await sleepAsync(300.milliseconds)
      let reclaimedBefore = spam[^1].reclaimCount

      check (await nodes[^1].sendSurbReply(surb, ReplyPayload)).isErr
      check ct.slotPool.nonCoverClaimed == 2
      check spam[^1].reclaimCount == reclaimedBefore

    asyncTest "failed reply claimed in an earlier epoch leaves the new epoch alone":
      let (nodes, _) = setupCountingNodes(10)
      let (surb, conn) = await nodes.requestSurb()
      defer:
        await conn.close()
        await stopNodes(nodes)
      let ct = nodes[^1].attachCover()

      await nodes.firstHop(surb).switch.stop()

      let reply = nodes[^1].sendSurbReply(surb, ReplyPayload)
      check ct.slotPool.nonCoverClaimed == 1

      ct.onEpochChange(2)
      discard ct.slotPool.claimSlot()

      check (await reply).isErr
      check ct.slotPool.nonCoverClaimed == 1

when defined(libp2p_mix_experimental_exit_is_dest):
  proc sendToExit(nodes: seq[MixProtocol]) {.async.} =
    ## With 5 nodes the path is two of nodes[1 .. 3] in random order, then the
    ## exit nodes[4], so the second of those two forwards to the exit.
    let res = await nodes[0].anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      @[1.byte],
      TestCodec,
      MixDestination.exitNode(nodes[4].switch.peerInfo.peerId),
      0,
    )
    check res.isOk

  suite "Slot refund - forward":
    asyncTeardown:
      checkTrackers()

    asyncTest "failed first dial refunds the slot and reclaims the proof":
      let (nodes, spam) = setupCountingNodes(5)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      let hops = nodes[1 .. 3].mapIt(it.attachCover())

      await nodes[4].switch.stop()
      await nodes.sendToExit()
      await sleepAsync(300.milliseconds)

      # The first hop's forward went out; the second hop's dial failed
      check hops.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 1
      check spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 1

    asyncTest "failure after a write attempt keeps the slot and the proof spent":
      let (nodes, spam) = setupCountingNodes(5)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)

      # Any of the three may go second, so send until each has almost certainly
      # cached a connection to the exit
      for _ in 0 ..< 40:
        await nodes.sendToExit()
      await sleepAsync(300.milliseconds)

      let hops = nodes[1 .. 3].mapIt(it.attachCover())

      await nodes[4].switch.stop()
      await sleepAsync(300.milliseconds)
      await nodes.sendToExit()
      await sleepAsync(300.milliseconds)

      check hops.mapIt(it.slotPool.nonCoverClaimed).foldl(a + b) == 2
      check spam[1 .. 3].mapIt(it.reclaimCount).foldl(a + b) == 0

suite "Slot refund - local send":
  asyncTeardown:
    checkTrackers()

  asyncTest "failed first dial refunds the slot and reclaims the proof":
    let (nodes, spam) = setupCountingNodes(10)
    await startNodes(nodes)
    defer:
      await stopNodes(nodes)
    let ct = nodes[0].attachCover()

    # Every candidate first hop is down, whichever path gets selected
    for node in nodes[1 ..^ 1]:
      await node.switch.stop()

    let res = await nodes[0].anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](), @[1.byte], TestCodec, nodes[^1].toMixDestination(), 0
    )

    check res.isErr
    check ct.slotPool.nonCoverClaimed == 0
    # Proves the send got as far as a proof, so the slot was claimed and refunded
    check spam[0].reclaimCount == 1

  asyncTest "failed send claimed in an earlier epoch leaves the new epoch alone":
    let (nodes, _) = setupCountingNodes(10)
    await startNodes(nodes)
    defer:
      await stopNodes(nodes)
    let ct = nodes[0].attachCover()

    for node in nodes[1 ..^ 1]:
      await node.switch.stop()

    let send = nodes[0].anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](), @[1.byte], TestCodec, nodes[^1].toMixDestination(), 0
    )
    check ct.slotPool.nonCoverClaimed == 1

    ct.onEpochChange(2)
    discard ct.slotPool.claimSlot()

    check (await send).isErr
    check ct.slotPool.nonCoverClaimed == 1

type
  HeldProofs = ref object of ReclaimCountingSpamProtection
    ## Counts the proofs that it makes. With a gate, a proof waits for the gate.
    generated: int
    gate: AsyncEvent
    waiting: bool
    failing: bool

  HoldStrategy = ref object of DelayStrategy
    ## The hold of a node before it writes a packet. A test sets it.
    hold: Delay

method generateProofAsync(
    self: HeldProofs, bindingData: seq[byte]
): Future[Result[ProofResult, string]] {.async: (raises: [CancelledError]).} =
  if not self.gate.isNil:
    self.waiting = true
    await self.gate.wait()
  if self.failing:
    return err("no proof")
  inc self.generated
  return ok(ProofResult(proof: newSeq[byte](self.proofSize), token: @[1.byte]))

method generateForEntry(self: HoldStrategy): Delay {.gcsafe, raises: [].} =
  NoDelay

method generateForIntermediate(
    self: HoldStrategy, encodedDelay: Delay
): Delay {.gcsafe, raises: [].} =
  self.hold

method generateForSender(self: HoldStrategy): Delay {.gcsafe, raises: [].} =
  self.hold

const LongHold = Delay(60_000)

proc setupHeldNodes(
    numNodes: int
): tuple[nodes: seq[MixProtocol], spam: seq[HeldProofs], delays: seq[HoldStrategy]] =
  ## As setupCountingNodes, with a proof provider and a hold that a test controls.
  let nodeInfos = MixNodeInfo.generateRandomMany(numNodes, rng())
  for mixNodeInfo in nodeInfos:
    let
      switch = createSwitch(mixNodeInfo.multiAddr, Opt.some(mixNodeInfo.libp2pPrivKey))
      spam = HeldProofs(proofSize: newReclaimCountingSpamProtection().proofSize)
      delay = HoldStrategy()
      node = MixProtocol.new(
        mixNodeInfo,
        switch,
        spamProtection = Opt.some(SpamProtection(spam)),
        delayStrategy = Opt.some(DelayStrategy(delay)),
      )
    node.registerDestReadBehavior(TestCodec, readLp(1024))
    switch.mount(node)
    node.nodePool.add(nodeInfos.includeAllExcept(mixNodeInfo))
    result.nodes.add(node)
    result.spam.add(spam)
    result.delays.add(delay)

suite "Slot refund - cancelled packet":
  asyncTeardown:
    checkTrackers()

  asyncTest "a send cancelled in its hold with a ready proof gets its slot and proof back":
    let (nodes, spam, delays) = setupHeldNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    delays[0].hold = LongHold

    let send = nodes[0].anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](), @[1.byte], TestCodec, nodes[^1].toMixDestination(), 0
    )
    checkUntilTimeout:
      spam[0].generated == 1
    check ct.slotPool.nonCoverClaimed == 1

    await send.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 1

  asyncTest "a send cancelled in its hold with a proof in work keeps its slot":
    ## The provider can have used the message ID of a proof that it did not
    ## finish, so the slot stays with it.
    let (nodes, spam, _) = setupHeldNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    spam[0].gate = newAsyncEvent()

    let send = nodes[0].anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](), @[1.byte], TestCodec, nodes[^1].toMixDestination(), 0
    )
    checkUntilTimeout:
      spam[0].waiting
    check ct.slotPool.nonCoverClaimed == 1

    await send.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 1
      spam[0].reclaimCount == 0

  asyncTest "a send whose proof fails gets its slot back":
    let (nodes, spam, _) = setupHeldNodes(5)
    startAndDeferStop(nodes)
    let ct = nodes[0].attachCover()
    spam[0].failing = true

    let sent = await nodes[0].anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](), @[1.byte], TestCodec, nodes[^1].toMixDestination(), 0
    )
    check:
      sent.isErr
      ct.slotPool.nonCoverClaimed == 0
      spam[0].reclaimCount == 0

  asyncTest "a reply cancelled in its hold with a ready proof gets its slot and proof back":
    let (nodes, spam, delays) = setupHeldNodes(5)
    startAndDeferStop(nodes)
    var id: SURBIdentifier
    id[0] = 1
    let exitPeerId = nodes[^1].switch.peerInfo.peerId
    let surb = nodes[0].buildSurb(id, exitPeerId, exitPeerId).expect("SURB")
    let ct = nodes[^1].attachCover()
    delays[^1].hold = LongHold

    let reply = nodes[^1].sendSurbReply(surb, ReplyPayload)
    checkUntilTimeout:
      spam[^1].generated == 1
    check ct.slotPool.nonCoverClaimed == 1

    await reply.cancelAndWait()
    check:
      ct.slotPool.nonCoverClaimed == 0
      spam[^1].reclaimCount == 1

  asyncTest "a forward that a stop cancels in its hold with a ready proof gets its slot and proof back":
    ## The path is the three middle nodes in random order. The first of them
    ## holds the packet.
    let (nodes, spam, delays) = setupHeldNodes(5)
    startAndDeferStop(nodes)
    let covers = nodes[1 .. 3].mapIt(it.attachCover())
    for delay in delays[1 .. 3]:
      delay.hold = LongHold

    let sent = await nodes[0].anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](), @[1.byte], TestCodec, nodes[^1].toMixDestination(), 0
    )
    check sent.isOk
    checkUntilTimeout:
      spam[1 .. 3].mapIt(it.generated).foldl(a + b) == 1
    let hop = toSeq(1 .. 3).filterIt(spam[it].generated == 1)[0]
    check covers[hop - 1].slotPool.nonCoverClaimed == 1

    await nodes[hop].stop()
    check:
      covers[hop - 1].slotPool.nonCoverClaimed == 0
      spam[hop].reclaimCount == 1
