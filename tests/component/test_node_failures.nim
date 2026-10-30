# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, stew/byteutils, sequtils
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
import libp2p_mix/mix_protocol
import libp2p_mix/pool
import libp2p_mix/sphinx
import libp2p_mix/delay_strategy

import ../tools/[lifecycle, unittest, crypto, host_pool]
import ../utils
import ../mock_mix

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

    # The first reply released the whole group, so the second found nothing —
    # group-atomic release, end to end.
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

  asyncTest "closing the connection releases credentials, and a second write is refused":
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
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(3))),
      )
      .expect("could not build connection")
    defer:
      destProto.release()

    await conn.writeLp(@[1.byte, 2, 3])
    discard await destProto.receivedMessages.get().wait(10.seconds)
    check sender.surbCredsLen == 3

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

  asyncTest "unusable records stay in shared books while valid paths deliver":
    let nodes = await setupMixNodes(6)
    let senderStore = PeerStore.new()
    var valid: seq[MixPubInfo]
    for i in 1 .. PathLength + 1:
      valid.add(nodes[0].nodePool.get(nodes[i].switch.peerInfo.peerId).get())
    # Read peers from the store books only, without the records that the fixture
    # added.
    nodes[0].pool = MixNodePool.new(senderStore, rng())
    for info in valid:
      senderStore[MixPubKeyBook][info.peerId] = info.mixPubKey
      senderStore[AddressBook][info.peerId] = @[info.multiAddr]
      senderStore[KeyBook][info.peerId] =
        PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)
    let invalidId = PeerId.random(rng()).get()
    let invalidAddress = MultiAddress.init("/ip4/0.0.0.0").get()
    senderStore[MixPubKeyBook][invalidId] = valid[0].mixPubKey
    senderStore[AddressBook][invalidId] = @[invalidAddress]
    senderStore[KeyBook][invalidId] =
      PublicKey(scheme: Secp256k1, skkey: valid[0].libp2pPubKey)
    check:
      nodes[0].pool.countUsable([]).get() == valid.len
      nodes[0].pool.usablePeer(invalidId).get().isNone
      senderStore[MixPubKeyBook].len == valid.len + 1
    let receiver = NoReplyProtocol.new()
    nodes[1].switch.mount(receiver)
    startAndDeferStop(nodes)
    let conn = nodes[0].toConnection(nodes[1].toMixDestination(), receiver.codec).get()
    defer:
      await conn.close()
    let payload = "test message".toBytes()
    await conn.writeLp(payload).wait(5.seconds)
    check (await receiver.receivedMessages.get().wait(5.seconds)).data == payload
    check:
      senderStore[MixPubKeyBook][invalidId] == valid[0].mixPubKey
      senderStore[AddressBook][invalidId] == @[invalidAddress]
      nodes[0].pool.countUsable([]).get() == valid.len
