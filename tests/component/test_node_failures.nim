# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, metrics, results, stew/byteutils, sequtils, strutils, tables
import
  libp2p/[
    protocols/ping,
    peerid,
    peerstore,
    multiaddress,
    switch,
    builders,
    crypto/crypto,
    crypto/secp,
  ]
import libp2p_mix
import libp2p_mix/mix_metrics
import libp2p_mix/mix_protocol
import libp2p_mix/serialization
import libp2p_mix/delay_strategy

import ../tools/[lifecycle, unittest, crypto]
import ../utils
import ../mock_mix

proc addUnusableMember(sender: MixProtocol): PeerId =
  ## Adds a pool member that no path can use to `sender`. The member has the
  ## keys of a valid member and an address with no transport.
  let store = sender.switch.peerStore
  let donor = sender.nodePool.peerIds().mapIt(sender.nodePool.get(it)).filterIt(
    it.isSome()
  )[0].get()
  let peerId = PeerId.random(rng()).expect("could not generate peerId")
  store[MixPubKeyBook][peerId] = donor.mixPubKey
  store[AddressBook][peerId] =
    @[MultiAddress.init("/ip4/0.0.0.0").expect("could not initialize multiaddr")]
  store[KeyBook][peerId] = PublicKey(scheme: Secp256k1, skkey: donor.libp2pPubKey)
  peerId

suite "Mix Protocol - Node Failures":
  asyncTeardown:
    checkTrackers()

  asyncTest "multiple SURBs - reply received when one path unavailable":
    ## 2 SURBs with separate paths.
    ## Stop a node from SURB[0]'s path after forward delivery.
    ## Reply must arrive via SURB[1].
    const TestCodec = "/delayed-response/test/1.0.0"
    const ReadLen = 1024

    let testPayload = "forward message".toBytes()
    let responseData = "reply via surviving SURB".toBytes()

    var received = newFuture[seq[byte]]()
    var proceed = newFuture[void]()

    let destProto = LPProtocol.new()
    destProto.codec = TestCodec
    destProto.handler = proc(
        conn: Connection, proto: string
    ) {.async: (raises: [CancelledError]).} =
      try:
        received.complete(await conn.readLp(ReadLen))
        await proceed
        await conn.writeLp(responseData)
      except CatchableError as e:
        raiseAssert e.msg

    let (nodes, mock) = await setupMixNodesWithMock(
      10, destReadBehavior = Opt.some((codec: TestCodec, callback: readLp(ReadLen)))
    )

    let (destNode, _) = await setupDestNode(destProto)

    # Force separate SURB paths: nodes[2..4] for SURB 0, nodes[5..7] for SURB 1
    mock.surbPeerSets = @[
      nodes[2 .. 4].mapIt(it.switch.peerInfo.peerId),
      nodes[5 .. 7].mapIt(it.switch.peerInfo.peerId),
    ]

    await startNodes(nodes)
    defer:
      await stopDestNode(destNode)
      await stopNodes(nodes)

    let conn = mock
      .toConnection(
        destNode.toMixDestination(),
        TestCodec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(2))),
      )
      .expect("could not build connection")

    await conn.writeLp(testPayload)

    check testPayload == await received.wait(10.seconds)

    # Stop a node from SURB[0]'s path
    let nodeToStop =
      nodes.filterIt(it.switch.peerInfo.peerId == mock.actualSurbPeers[0][0])[0]
    await nodeToStop.switch.stop()

    # Signal dest node to send reply — must arrive via SURB[1]
    proceed.complete()

    let response = await conn.readLp(ReadLen).wait(10.seconds)
    await conn.close()

    check:
      response == responseData
      mock.receivedPacketCount == 1

  asyncTest "multiple SURBs - both replies received, only one delivered":
    ## 2 SURBs, all paths healthy. Exit sends reply via ALL SURBs.
    ## Both replies arrive at the sender's mix layer,
    ## but only one is delivered to the application.
    let (nodes, mock) = await setupMixNodesWithMock(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )

    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))

    await startNodes(nodes)
    defer:
      await stopDestNode(destNode)
      await stopNodes(nodes)

    let conn = mock
      .toConnection(
        destNode.toMixDestination(),
        pingProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(2))),
      )
      .expect("could not build connection")
    defer:
      await conn.close()

    let response = await pingProto.ping(conn)
    check response != 0.seconds

    # Second read: no more replies delivered
    expect LPStreamEOFError:
      var buf: byte
      await conn.readExactly(addr buf, 1)

    # Both SURB replies arrived at the mix layer
    checkUntilTimeout:
      mock.receivedPacketCount == 2

    # Each arrived reply consumes its own credential, even though the legacy
    # stream adapter exposes only the first response.
    check mock.surbCredsLen == 0

  asyncTest "native send queue receives one response per SURB":
    let (nodes, mock) = await setupMixNodesWithMock(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )
    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    await startNodes(nodes)
    defer:
      await stopDestNode(destNode)
      await stopNodes(nodes)

    let incoming = newAsyncQueue[seq[byte]]()
    let payload = newSeqWith(32, byte(42))
    let sent = await mock.anonymizeLocalProtocolSend(
      incoming, payload, pingProto.codec, destNode.toMixDestination(), byte(2)
    )
    check sent.isOk()
    check (await incoming.get().wait(10.seconds)) == payload
    check (await incoming.get().wait(10.seconds)) == payload
    check mock.surbCredsLen == 0

  asyncTest "sender times out when destination is unreachable":
    ## Exit node gets DialFailedError and must not fabricate an empty SURB reply.
    let (nodes, mock) = await setupMixNodesWithMock(
      10,
      destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32))),
      delayStrategy = Opt.some(DelayStrategy(FixedDelayStrategy(delay: 0))),
    )

    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    let destPeerId = destNode.peerInfo.peerId
    let destAddr = destNode.peerInfo.addrs[0]
    await stopDestNode(destNode)

    startAndDeferStop(nodes)

    let conn = mock
      .toConnection(
        MixDestination.init(destPeerId, destAddr),
        pingProto.codec,
        MixParameters(
          expectReply: Opt.some(true),
          numSurbs: Opt.some(byte(1)),
          replyTimeout: Opt.some(1.seconds),
        ),
      )
      .expect("could not build connection")
    defer:
      await conn.close()

    await conn.write(@[1.byte, 2, 3, 4, 5])

    expect LPStreamEOFError:
      discard await conn.readLp(1024).wait(10.seconds)

    check:
      mock.receivedPacketCount == 0
      mock.surbCredsLen == 0

  asyncTest "reply timeout releases the SURB credentials":
    ## Destination never answers, so no reply can ever come back. readOnce
    ## must give up and drop the credentials rather than hold them.
    const TestCodec = "/silent/test/1.0.0"

    let destProto = SilentProtocol.new(TestCodec)
    let nodes = await setupMixNodes(
      10,
      destReadBehavior = Opt.some((codec: TestCodec, callback: readLp(1024))),
      delayStrategy = Opt.some(DelayStrategy(FixedDelayStrategy(delay: 0))),
    )
    startAndDeferStop(nodes)

    let (destNode, _) = await setupDestNode(destProto)
    defer:
      await stopDestNode(destNode)

    let sender = nodes[0]
    check sender.surbCredsLen == 0

    let conn = sender
      .toConnection(
        destNode.toMixDestination(),
        TestCodec,
        MixParameters(
          expectReply: Opt.some(true),
          numSurbs: Opt.some(byte(2)),
          replyTimeout: Opt.some(2.seconds),
        ),
      )
      .expect("could not build connection")
    defer:
      await conn.close()

    # Declared last so it runs first: the handler is parked, and stopDestNode
    # would otherwise wait on it.
    defer:
      destProto.release()

    await conn.writeLp(@[1.byte, 2, 3])
    discard await destProto.receivedMessages.get().wait(10.seconds)
    check sender.surbCredsLen == 2

    # libp2p convention: a timeout surfaces as end-of-stream, not a distinct
    # error type, so existing protocol code needs no mix-specific handling.
    expect LPStreamEOFError:
      discard await conn.readLp(1024).wait(10.seconds)

    check sender.surbCredsLen == 0

  asyncTest "default reply connection uses one SURB, releases on close, and refuses a second write":
    ## Prompt reclamation well inside the store TTL, plus the single-exchange
    ## guard — both properties of one live connection, so one setup covers them.
    const TestCodec = "/silent-2/test/1.0.0"

    let destProto = SilentProtocol.new(TestCodec)
    let nodes = await setupMixNodes(
      10,
      destReadBehavior = Opt.some((codec: TestCodec, callback: readLp(1024))),
      delayStrategy = Opt.some(DelayStrategy(FixedDelayStrategy(delay: 0))),
    )
    startAndDeferStop(nodes)

    let (destNode, _) = await setupDestNode(destProto)
    defer:
      await stopDestNode(destNode)

    let sender = nodes[0]

    let conn = sender
      .toConnection(
        destNode.toMixDestination(),
        TestCodec,
        MixParameters(expectReply: Opt.some(true)),
      )
      .expect("could not build connection")
    defer:
      destProto.release()

    await conn.writeLp(@[1.byte, 2, 3])
    discard await destProto.receivedMessages.get().wait(10.seconds)
    check sender.surbCredsLen == 1

    # A second reply would land in a queue nobody drains, so it is refused.
    expect LPStreamError:
      await conn.writeLp(@[4.byte, 5, 6])

    await conn.close()
    check sender.surbCredsLen == 0

  asyncTest "a send that never leaves the node releases its credentials":
    ## Every mix node is unreachable, so sendPacket fails after the reply
    ## credentials were already registered. No reply can ever release them,
    ## so the send path must.
    let nodes = await setupMixNodes(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )

    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    defer:
      await stopDestNode(destNode)

    await startNodes(nodes)
    defer:
      await stopNodes(nodes)

    let sender = nodes[0]

    # Stop every other node. They stay in the sender peerStore, so path
    # selection still succeeds and the failure lands in sendPacket.
    for node in nodes[1 ..^ 1]:
      await node.switch.stop()

    let conn = sender
      .toConnection(
        destNode.toMixDestination(),
        pingProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(4))),
      )
      .expect("could not build connection")
    defer:
      await conn.close()

    expect LPStreamError:
      await conn.write(@[1.byte, 2, 3, 4, 5])

    check sender.surbCredsLen == 0

  asyncTest "forward path node down - hop 2 or exit":
    ## With 4 mix nodes the sender (node 0) has a pool of exactly 3 nodes.
    ## After sending, we identify the first hop, then stop one of the other two nodes.

    ## The high delay ensures intermediaries hold the packet long enough
    ## to stop the target node before it is forwarded.
    let delayStrategy: DelayStrategy = FixedDelayStrategy(delay: 1000)

    let nodes = await setupMixNodes(4, delayStrategy = Opt.some(delayStrategy))
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    let sender = nodes[0]

    let conn = sender.toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    defer:
      await conn.close()

    await conn.writeLp(@[1.byte, 2, 3])

    # Filter out the first hop
    let nodesToStop =
      nodes[1 ..^ 1].filterIt(not sender.switch.isConnected(it.switch.peerInfo.peerId))

    # Stop hop 2 or exit
    await nodesToStop[0].switch.stop()

    # Destination must never receive the message
    # Wait at least 5s to ensure failure is from the stopped node
    expect AsyncTimeoutError:
      discard await nrProto.receivedMessages.get().wait(5.seconds)

  asyncTest "a node with an invalid multiaddress is on no path and stays in the pool":
    ## A draw skips a pool member with no usable address. The member keeps its
    ## mix key, because a later record can give it an address.
    let nodes = await setupMixNodes(5)
    let sender = nodes[0]
    let destination = nodes[1]
    let invalidPeerId = sender.addUnusableMember()

    let nrProto = NoReplyProtocol.new()
    destination.switch.mount(nrProto)
    startAndDeferStop(nodes)

    let testPayload = "test message".toBytes()
    for _ in 0 ..< 20:
      let conn = sender
        .toConnection(destination.toMixDestination(), nrProto.codec)
        .expect("could not build connection")
      await conn.writeLp(testPayload)
      discard await nrProto.receivedMessages.get().wait(5.seconds)
      await conn.close()

    check invalidPeerId in sender.switch.peerStore[MixPubKeyBook]

  asyncTest "a reply path and a cover path draw again after a node with an invalid multiaddress":
    ## A reply path or a cover path that draws such a node must draw again. A
    ## failed build fails the send.
    let nrProto = NoReplyProtocol.new()
    let nodes = await setupMixNodes(
      5, destReadBehavior = Opt.some((codec: nrProto.codec, callback: readLp(1024)))
    )
    let sender = nodes[0]
    let destination = nodes[1]
    discard sender.addUnusableMember()

    destination.switch.mount(nrProto)
    startAndDeferStop(nodes)

    let testPayload = "test message".toBytes()
    for _ in 0 ..< 20:
      let conn = sender
        .toConnection(
          destination.toMixDestination(),
          nrProto.codec,
          MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
        )
        .expect("could not build connection")
      await conn.writeLp(testPayload)
      discard await nrProto.receivedMessages.get().wait(5.seconds)
      await conn.close()

      let cover = await sender.buildCoverPacket()
      check cover.isOk

  asyncTest "the pool size check does not count a destination with no hop address":
    ## The sender's pool holds two usable members plus the destination, which has no
    ## hop address, but a path needs three nodes other than the destination.
    let nodes = await setupMixNodes(3)
    let sender = nodes[0]
    let destination = sender.addUnusableMember()
    startAndDeferStop(nodes)

    let sent = await sender.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      "test message".toBytes(),
      "/test/1.0.0",
      MixDestination.init(
        destination,
        MultiAddress.init("/ip4/127.0.0.1/tcp/4242").expect(
          "could not create multiaddr"
        ),
      ),
      0,
    )
    check:
      sent.isErr
      sent.error.startsWith("No. of public mix nodes (2)")

  asyncTest "a send that runs out of usable members counts LOW_MIX_POOL":
    ## The sender's pool holds two usable members and one with no hop address, but a
    ## path needs three nodes.
    let nodes = await setupMixNodes(3)
    let sender = nodes[0]
    discard sender.addUnusableMember()
    startAndDeferStop(nodes)
    let lowPoolBefore = errorCount("Entry", "LOW_MIX_POOL")

    let sent = await sender.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      "test message".toBytes(),
      "/test/1.0.0",
      MixDestination.init(
        PeerId.random(rng()).expect("could not generate peerId"),
        MultiAddress.init("/ip4/127.0.0.1/tcp/4242").expect(
          "could not create multiaddr"
        ),
      ),
      0,
    )
    check:
      sent.isErr
      errorCount("Entry", "LOW_MIX_POOL") == lowPoolBefore + 1

  asyncTest "a reply path that runs out of usable members counts LOW_MIX_POOL":
    ## The reply path needs two nodes other than the exit, but apart from the exit
    ## the pool has only one usable member and one with no hop address.
    let nodes = await setupMixNodes(3)
    let sender = nodes[0]
    discard sender.addUnusableMember()
    let lowPoolBefore = errorCount("Entry/SURB", "LOW_MIX_POOL")

    let surb = sender.buildSurb(
      rng().generate(SURBIdentifier),
      PeerId.random(rng()).expect("could not generate peerId"),
      nodes[1].switch.peerInfo.peerId,
    )
    check:
      surb.isErr
      errorCount("Entry/SURB", "LOW_MIX_POOL") == lowPoolBefore + 1

  asyncTest "a reply path with too few members counts LOW_MIX_POOL":
    ## The pool has three members, but two of them are the exit and the destination,
    ## and the reply path needs two nodes that are neither.
    let nodes = await setupMixNodes(4)
    let sender = nodes[0]
    let lowPoolBefore = errorCount("Entry/SURB", "LOW_MIX_POOL")

    let surb = sender.buildSurb(
      rng().generate(SURBIdentifier),
      nodes[2].switch.peerInfo.peerId,
      nodes[1].switch.peerInfo.peerId,
    )
    check:
      surb.isErr
      surb.error.startsWith("Not enough mix nodes for a reply path")
      errorCount("Entry/SURB", "LOW_MIX_POOL") == lowPoolBefore + 1

  asyncTest "a cover path that runs out of usable members counts LOW_MIX_POOL":
    ## The cover path needs two nodes, but the pool has only one usable member and
    ## one with no hop address.
    let nodes = await setupMixNodes(2)
    let sender = nodes[0]
    discard sender.addUnusableMember()
    let lowPoolBefore = errorCount("Cover", "LOW_MIX_POOL")

    let cover = await sender.buildCoverPacket()
    check:
      cover.isErr
      errorCount("Cover", "LOW_MIX_POOL") == lowPoolBefore + 1

  asyncTest "a cover path with too few members counts LOW_MIX_POOL":
    ## The pool has one member, but the cover path needs two.
    let nodes = await setupMixNodes(2)
    let sender = nodes[0]
    let lowPoolBefore = errorCount("Cover", "LOW_MIX_POOL")

    let cover = await sender.buildCoverPacket()
    check:
      cover.isErr
      errorCount("Cover", "LOW_MIX_POOL") == lowPoolBefore + 1

  asyncTest "start sets mix_pool_size to the pool members that a path can use":
    ## Every node has two usable pool members and one with no hop address.
    ## The gauge is process-wide, so the test gives every node the same pool count.
    let nodes = await setupMixNodes(3)
    for node in nodes:
      discard node.addUnusableMember()
    startAndDeferStop(nodes)

    check:
      nodes[0].nodePool.len == 3
      mix_pool_size.value == 2

  asyncTest "a send and a cover packet set mix_pool_size":
    ## A node's first path build after `start` always counts the pool, so one node
    ## sends and another builds a cover packet.
    let nodes = await setupMixNodes(3)
    let sender = nodes[0]
    let coverNode = nodes[1]
    startAndDeferStop(nodes)
    check mix_pool_size.value == 2

    discard sender.nodePool.remove(nodes[1].switch.peerInfo.peerId)
    discard await sender.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      "test message".toBytes(),
      "/test/1.0.0",
      MixDestination.init(
        PeerId.random(rng()).expect("could not generate peerId"),
        MultiAddress.init("/ip4/127.0.0.1/tcp/4242").expect(
          "could not create multiaddr"
        ),
      ),
      0,
    )
    check mix_pool_size.value == 1

    discard coverNode.nodePool.remove(nodes[0].switch.peerInfo.peerId)
    discard coverNode.nodePool.remove(nodes[2].switch.peerInfo.peerId)
    discard await coverNode.buildCoverPacket()
    check mix_pool_size.value == 0

  asyncTest "a second path build does not count the pool again at once":
    ## The two path builds are much less than `PoolSizeInterval` apart, so only the
    ## first one counts the pool.
    let nodes = await setupMixNodes(3)
    let sender = nodes[0]
    startAndDeferStop(nodes)
    check mix_pool_size.value == 2

    discard sender.nodePool.remove(nodes[1].switch.peerInfo.peerId)
    discard await sender.buildCoverPacket()
    check mix_pool_size.value == 1

    discard sender.nodePool.remove(nodes[2].switch.peerInfo.peerId)
    discard await sender.buildCoverPacket()
    check mix_pool_size.value == 1

  asyncTest "a node with the public hop address policy has no usable peer on the local host":
    let nodes = await setupMixNodes(5, hopAddressPolicy = publicHopAddressPolicy)
    let sender = nodes[0]
    let nrProto = NoReplyProtocol.new()
    nodes[1].switch.mount(nrProto)
    startAndDeferStop(nodes)

    check:
      sender.nodePool.len == 4
      sender.nodePool.peerIds().allIt(sender.nodePool.get(it).isNone)

    let conn = sender.toConnection(nodes[1].toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    defer:
      await conn.close()
    var failure = ""
    try:
      await conn.writeLp("test message".toBytes())
    except LPStreamError as exc:
      failure = exc.msg
    check "Ran out of available mix nodes" in failure

  when defined(libp2p_mix_experimental_exit_is_dest):
    proc exitSendFailure(nodes: seq[MixProtocol]): Future[string] {.async.} =
      ## Sends from the first node to the second node as the exit, and returns
      ## the error of the send.
      let nrProto = NoReplyProtocol.new()
      nodes[1].switch.mount(nrProto)
      startAndDeferStop(nodes)

      let conn = nodes[0]
        .toConnection(
          MixDestination.exitNode(nodes[1].switch.peerInfo.peerId), nrProto.codec
        )
        .expect("could not build connection")
      defer:
        await conn.close()
      try:
        await conn.writeLp("test message".toBytes())
      except LPStreamError as exc:
        return exc.msg
      ""

    asyncTest "a send to an exit with no usable address fails at once":
      ## The exit is the last hop of the path, so the sender needs a hop address
      ## for it.
      let nodes = await setupMixNodes(5)
      discard
        nodes[0].switch.peerStore[AddressBook].del(nodes[1].switch.peerInfo.peerId)

      check "Destination is not a mix node with a usable address" in
        await exitSendFailure(nodes)

    asyncTest "a send to an exit with no address that the policy accepts fails at once":
      let nodes = await setupMixNodes(5, hopAddressPolicy = publicHopAddressPolicy)

      check "Destination is not a mix node with a usable address" in
        await exitSendFailure(nodes)
