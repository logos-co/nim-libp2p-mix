# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos, results
import libp2p/[switch, peerid, multiaddress]
import libp2p_mix
import
  libp2p_mix/[mix_protocol, mix_node, cover_traffic, delay_strategy, spam_protection]
import ../tools/[lifecycle, unittest, crypto]
import ../[utils, spam_protection_impl]

const ReplyParams = MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8))

proc exchange(
    sender: MixProtocol, destination: MixDestination, codec: string, value: byte
) {.async.} =
  let conn = sender.toConnection(destination, codec, ReplyParams).expect("connection")
  defer:
    await conn.close()
  await conn.writeLp(@[value]).wait(5.seconds)
  let reply = await conn.readLp(1024).wait(5.seconds)
  check reply == @[value]

suite "Hop stream cache":
  asyncTeardown:
    checkTrackers()

  asyncTest "concurrent requests and retries reuse one cached stream per peer":
    let echoProto = EchoProtocol.new()
    let nodes = await setupMixNodes(
      5, destReadBehavior = Opt.some((codec: echoProto.codec, callback: readLp(1024)))
    )
    nodes[^1].switch.mount(echoProto)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let destination = nodes[^1].toMixDestination()
    for round in 0 .. 1:
      var pending: seq[Future[void]]
      for i in 0 ..< 8:
        pending.add(exchange(sender, destination, echoProto.codec, i.byte))
      await allFutures(pending)
      for request in pending:
        await request
      let streams = outgoingMixStreams(sender.switch)
      check streams.len > 0
      # One cached stream for each peer. A second stream to the same peer is
      # the duplicate that this test exists to catch.
      check streams.mapIt(it.peerId).deduplicate().len == streams.len
      if round == 0:
        # Close the cached streams and keep the cache entries, as a peer reset does.
        await allFutures(streams.mapIt(it.close()))

  asyncTest "protocol stop fails a cover send that waits on a dial and refuses a new dial":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)

    let hold = HoldingServer.new()
    defer:
      await hold.close()

    let hopPeerId = PeerId.random(rng()).expect("peer id")
    let hopAddr = hold.address()
    let errorsBefore = errorCount("Cover", "SEND_FAILED")
    let sending = nodes[0].sendCoverPacket(hopPeerId, hopAddr, @[1.byte])
    checkUntilTimeout:
      hold.connections.len == 1
    check not sending.finished

    # The stop cancels the dial. The send fails, and the counters record no
    # failure of the hop.
    await nodes[0].stop()
    let stopped = await sending.wait(2.seconds)
    check:
      stopped.isErr
      errorCount("Cover", "SEND_FAILED") == errorsBefore
    # A send that the stop refuses counts nothing either.
    let refused = await nodes[0].sendCoverPacket(hopPeerId, hopAddr, @[1.byte])
    check:
      refused.isErr
      errorCount("Cover", "SEND_FAILED") == errorsBefore
      hold.connections.len == 1

  asyncTest "protocol restart dials again":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)
    let hold = HoldingServer.new()
    defer:
      await hold.close()

    await nodes[0].stop()
    await nodes[0].start()
    let sending = nodes[0].sendCoverPacket(
      PeerId.random(rng()).expect("peer id"), hold.address(), @[1.byte]
    )
    checkUntilTimeout:
      hold.connections.len == 1
    await sending.cancelAndWait()

  asyncTest "protocol stop closes the cached hop streams":
    let echoProto = EchoProtocol.new()
    let nodes = await setupMixNodes(
      5, destReadBehavior = Opt.some((codec: echoProto.codec, callback: readLp(1024)))
    )
    nodes[^1].switch.mount(echoProto)
    startAndDeferStop(nodes)
    let sender = nodes[0]

    await exchange(sender, nodes[^1].toMixDestination(), echoProto.codec, 7)
    check outgoingMixStreams(sender.switch).len > 0
    await sender.stop()
    check outgoingMixStreams(sender.switch).len == 0

  asyncTest "protocol stop fails a send that waits on a dial and refunds its slot and proof":
    # A node that counts the proofs it reclaims, with a slot pool whose epochs
    # change only when the test says so.
    let info = MixNodeInfo.generateRandom(0, rng())
    let spam = newReclaimCountingSpamProtection()
    let node = MixProtocol.new(
      info,
      createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey)),
      spamProtection = Opt.some(SpamProtection(spam)),
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
    )
    node.switch.mount(node)
    startAndDeferStop(@[node])
    # Attached after the start, so no emission loop runs and only the send under
    # test claims a slot and dials the server. The epoch is set by hand.
    let cover =
      ConstantRateCoverTraffic.new(totalSlots = 4, useInternalEpochTimer = false)
    cover.onEpochChange(1)
    node.coverTraffic = Opt.some(CoverTraffic(cover))

    let hold = HoldingServer.new()
    defer:
      await hold.close()

    # Every pool member has the address of the server, so the first hop of any
    # path keeps the send in its dial.
    for member in MixNodeInfo.generateRandomMany(3, rng()):
      var hop = member.toMixPubInfo()
      hop.multiAddr = hold.address()
      node.nodePool.add(hop)
    let destination = MixNodeInfo.generateRandom(0, rng())
    let errorsBefore = errorCount("Entry", "SEND_FAILED")
    let sending = node.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      @[1.byte],
      "/test/1.0.0",
      MixDestination.init(destination.peerId, destination.multiAddr),
      0,
    )
    checkUntilTimeout:
      hold.connections.len == 1
    check cover.slotPool.nonCoverClaimed == 1

    # The packet never left this node, so the send gives its slot and proof back.
    await node.stop()
    let stopped = await sending.wait(2.seconds)
    check:
      stopped.isErr
      errorCount("Entry", "SEND_FAILED") == errorsBefore
      cover.slotPool.nonCoverClaimed == 0
      spam.reclaimCount == 1
