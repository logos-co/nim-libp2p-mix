# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, strutils]
import chronos, results
import libp2p/[switch, peerstore, multiaddress]
import libp2p_mix
import
  libp2p_mix/
    [mix_protocol, mix_node, curve25519, delay, multiaddr, serialization, sphinx]
import ../tools/[lifecycle, unittest, crypto]
import ../utils

when defined(libp2p_mix_experimental_exit_is_dest):
  const
    TestCodec = "/mix/test/hop-backoff/1.0.0"
    DialFailed = "Failed to dial to next hop"
    RedialFailed = "Failed to redial next hop"

  proc closedPortAddress(): MultiAddress =
    ## An address where nothing listens, so a dial to it fails at once.
    MultiAddress.init("/ip4/127.0.0.1/tcp/1").expect("address")

  proc makeSurb(path: seq[MixPubInfo], firstHopAddr: MultiAddress): SURB =
    ## Makes a SURB whose reply goes through `path`.
    ## `firstHopAddr` is the address that the SURB gives for the first hop.
    var hops: seq[Hop]
    for i, node in path:
      let address = if i == 0: firstHopAddr else: node.multiAddr
      hops.add(Hop.init(multiAddrToBytes(node.peerId, address).expect("hop")))
    let surb = createSURB(
      path.mapIt(it.mixPubKey),
      path.mapIt(NoDelay),
      hops,
      rng().generate(SURBIdentifier),
      rng(),
    )
    surb.expect("SURB")

  proc firstHopFailed(
      sender: MixProtocol, exit: MixProtocol, failure = DialFailed
  ): Future[bool] {.async.} =
    let res = await sender.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      @[1.byte],
      TestCodec,
      MixDestination.exitNode(exit.switch.peerInfo.peerId),
      0,
    )
    if res.isErr and failure in res.error:
      return true
    if res.isErr:
      checkpoint res.error
    check res.isOk
    false

  proc firstHopFailures(
      sender: MixProtocol, exit: MixProtocol, sends: int
  ): Future[int] {.async.} =
    var failures = 0
    for _ in 0 ..< sends:
      if await sender.firstHopFailed(exit):
        inc failures
    failures

  proc sendUntilFirstHopFails(
      sender: MixProtocol, exit: MixProtocol, maxSends: int, failure = DialFailed
  ): Future[bool] {.async.} =
    for _ in 0 ..< maxSends:
      if await sender.firstHopFailed(exit, failure):
        return true
    false

  proc coverSelects(
      sender: MixProtocol, peerId: PeerId, builds: int
  ): Future[bool] {.async.} =
    for _ in 0 ..< builds:
      let cover = (await sender.buildCoverPacket(0)).expect("cover packet")
      if cover.firstHopPeerId == peerId:
        return true
    false

  suite "Hop backoff":
    asyncTeardown:
      checkTrackers()

    asyncTest "a hop that failed a dial is not selected again during the backoff":
      # nodes[0] sends to the exit nodes[5] through nodes[1 .. 4]. nodes[4] is
      # stopped, so without the backoff a quarter of the first hops are dead.
      let nodes = await setupMixNodes(6)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      await nodes[4].switch.stop()
      let first = await nodes[0].sendUntilFirstHopFails(nodes[5], 40)
      check first
      let later = await nodes[0].firstHopFailures(nodes[5], 30)
      check later == 0
      # The cover path draws its first node with the same filter.
      let coverSelected =
        await nodes[0].coverSelects(nodes[4].switch.peerInfo.peerId, 40)
      check not coverSelected

    asyncTest "a send succeeds when its later hops need a backed off hop":
      # Five nodes leave three candidates, nodes[1 .. 3], and a path draws all
      # three. So the backed off nodes[3] must be a later hop.
      let nodes = await setupMixNodes(5)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      await nodes[3].switch.stop()
      let first = await nodes[0].sendUntilFirstHopFails(nodes[4], 40)
      check first
      let later = await nodes[0].firstHopFailures(nodes[4], 30)
      check later == 0

    asyncTest "a send fails when each first hop candidate is backed off":
      let nodes = await setupMixNodes(5)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      for i in 1 .. 3:
        await nodes[i].switch.stop()
      # Each failed dial backs one more candidate off.
      for _ in 1 .. 3:
        let failed = await nodes[0].sendUntilFirstHopFails(nodes[4], 40)
        check failed
      let sent = await nodes[0].anonymizeLocalProtocolSend(
        newAsyncQueue[seq[byte]](),
        @[1.byte],
        TestCodec,
        MixDestination.exitNode(nodes[4].switch.peerInfo.peerId),
        0,
      )
      check:
        sent.isErr
        "Ran out of available mix nodes" in sent.error

    asyncTest "a hop whose backoff ended is selected again":
      # A zero backoff ends at once, so the next send can select the hop again.
      let nodes = await setupMixNodes(6, hopBackoff = ZeroDuration)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      await nodes[4].switch.stop()
      let first = await nodes[0].sendUntilFirstHopFails(nodes[5], 40)
      check first
      let again = await nodes[0].sendUntilFirstHopFails(nodes[5], 40)
      check again

    asyncTest "a dial that succeeds clears the backoff":
      let nodes = await setupMixNodes(6)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      let hop = nodes[4].localMixPubInfo()
      await nodes[4].switch.stop()
      let first = await nodes[0].sendUntilFirstHopFails(nodes[5], 40)
      check first
      await nodes[4].switch.start()
      # A normal send never selects a backed off hop, so a direct cover send forces
      # the dial. The payload is not a valid packet, and the receiver drops it.
      let sent = await nodes[0].sendCoverPacket(hop.peerId, hop.multiAddr, @[1.byte])
      check sent.isOk
      let coverSelected = await nodes[0].coverSelects(hop.peerId, 100)
      check coverSelected

    asyncTest "a first hop whose redial fails is backed off":
      # A send writes to the cached stream of its first hop.
      # It dials again when that stream is broken.
      let nodes = await setupMixNodes(6)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      let hop = nodes[4].localMixPubInfo()
      # A direct cover send caches a stream to the hop.
      let cached = await nodes[0].sendCoverPacket(hop.peerId, hop.multiAddr, @[1.byte])
      check cached.isOk
      await nodes[4].switch.stop()
      checkUntilTimeout:
        not nodes[0].switch.isConnected(hop.peerId)
      let redial = await nodes[0].sendUntilFirstHopFails(nodes[5], 40, RedialFailed)
      check redial
      let later = await nodes[0].firstHopFailures(nodes[5], 30)
      check later == 0

    asyncTest "a first hop that refuses the mix protocol on an open connection is backed off":
      # A pool member can hold a connection for another protocol and refuse mix.
      # Each send that draws it as the first hop fails.
      let nodes = await setupMixNodes(5)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      let (plain, _) = await setupDestNode(NoReplyProtocol.new())
      defer:
        await stopDestNode(plain)
      let peerId = plain.peerInfo.peerId
      let address = plain.peerInfo.addrs[0]
      let (_, mixPubKey) = generateKeyPair().expect("mix key pair")
      nodes[0].nodePool.add(
        MixPubInfo.init(peerId, address, mixPubKey, plain.peerInfo.publicKey.skkey)
      )
      await nodes[0].switch.connect(peerId, @[address])
      let sent = await nodes[0].sendCoverPacket(peerId, address, @[1.byte])
      check:
        sent.isErr
        nodes[0].switch.isConnected(peerId)
      let coverSelected = await nodes[0].coverSelects(peerId, 100)
      check not coverSelected

    asyncTest "a dial that the stopped protocol refuses does not back the hop off":
      # The protocol refuses each dial while it is stopped.
      # That is no failure of the hop.
      let nodes = await setupMixNodes(5)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      let hop = nodes[1].localMixPubInfo()
      await nodes[0].stop()
      let refused = await nodes[0].sendCoverPacket(hop.peerId, hop.multiAddr, @[1.byte])
      check refused.isErr
      await nodes[0].start()
      let coverSelected = await nodes[0].coverSelects(hop.peerId, 100)
      check coverSelected

    asyncTest "a forwarded packet with a wrong address does not back its next hop off":
      # The sender of a packet gives the address of the next hop of a forward.
      # So a sender could make a node skip a reachable peer as its own first hop.
      # nodes[0] sends to the exit nodes[4] through two of nodes[1 .. 3].
      # It has a wrong address for nodes[3].
      let nodes = await setupMixNodes(5)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      let target = nodes[3].switch.peerInfo.peerId
      nodes[0].switch.peerStore[AddressBook].set(
        target, @[closedPortAddress()], AddressConfidence.Infinite
      )
      let failuresBefore = errorCount("Intermediate", "DIAL_FAILED")
      for _ in 0 ..< 40:
        discard await nodes[0].firstHopFailed(nodes[4])
      checkUntilTimeout:
        errorCount("Intermediate", "DIAL_FAILED") > failuresBefore
      for i in 1 .. 2:
        let coverSelected = await nodes[i].coverSelects(target, 100)
        check coverSelected

    asyncTest "a reply with a wrong address in its SURB does not back the first hop off":
      # The sender of a request gives the address of the first hop of the reply.
      # So a sender could make the node that replies skip a reachable peer.
      let nodes = await setupMixNodes(5)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      let hop = nodes[1].localMixPubInfo()
      let path = @[hop, nodes[2].localMixPubInfo(), nodes[3].localMixPubInfo()]
      let wrong = makeSurb(path, closedPortAddress())
      # No stream to the hop is cached, so the reply fails its first dial.
      let firstDial = await nodes[0].sendSurbReply(wrong, @[1.byte])
      check:
        firstDial.isErr
        DialFailed in firstDial.error
      var coverSelected = await nodes[0].coverSelects(hop.peerId, 100)
      check coverSelected
      # A reply that leaves caches a stream to the hop.
      # The stream then breaks, so the next reply fails its redial.
      let sent = await nodes[0].sendSurbReply(makeSurb(path, hop.multiAddr), @[1.byte])
      check sent.isOk
      await nodes[0].switch.disconnect(hop.peerId)
      checkUntilTimeout:
        not nodes[0].switch.isConnected(hop.peerId)
      let redial = await nodes[0].sendSurbReply(wrong, @[1.byte])
      check:
        redial.isErr
        RedialFailed in redial.error
      coverSelected = await nodes[0].coverSelects(hop.peerId, 100)
      check coverSelected
