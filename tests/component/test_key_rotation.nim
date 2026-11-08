# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import libp2p/[protocols/ping, switch]
import libp2p_mix
import libp2p_mix/[curve25519, delay_strategy, key_rotation, mix_protocol]

import ../tools/[lifecycle, unittest, crypto]
import ../utils

proc setupKeyRotationNodes(
    numNodes: int,
    destReadBehavior = Opt.none(tuple[codec: string, callback: DestReadBehavior]),
    config = KeyRotationConfig.init().expect("default config"),
): tuple[nodes: seq[MixProtocol], rings: seq[MixKeyRing]] =
  ## Nodes that each rotate their mix key. Each pool holds the first key of every
  ## other node.
  var
    nodes: seq[MixProtocol]
    rings: seq[MixKeyRing]
    infos: seq[MixPubInfo]
  for mixNodeInfo in MixNodeInfo.generateRandomMany(numNodes, rng()):
    let ring = MixKeyRing.new(config, rng(), replayTableCapacity = 1024)
    ring.update()
    var info = mixNodeInfo.toMixPubInfo()
    info.mixPubKey = ring.currentPublicKey().expect("current key")

    let switch =
      createSwitch(mixNodeInfo.multiAddr, Opt.some(mixNodeInfo.libp2pPrivKey))
    let node = MixProtocol.new(
      mixNodeInfo,
      switch,
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
      keyRing = Opt.some(ring),
    )
    if destReadBehavior.isSome():
      let (codec, callback) = destReadBehavior.get()
      node.registerDestReadBehavior(codec, callback)
    switch.mount(node)
    nodes.add(node)
    rings.add(ring)
    infos.add(info)

  for index, node in nodes:
    node.nodePool.add(infos.filterIt(it.peerId != infos[index].peerId))
  (nodes, rings)

proc fastRotationConfig(): KeyRotationConfig =
  KeyRotationConfig
    .init(
      rotationInterval = 1.seconds,
      graceWindow = 2.seconds,
      replacedRecordLifetime = ZeroDuration,
      maxTransit = 100.milliseconds,
    )
    .expect("fast rotation config")

proc firstKeys(rings: seq[MixKeyRing]): seq[Opt[FieldElement]] =
  rings.mapIt(it.currentPublicKey())

proc allRotated(rings: seq[MixKeyRing], first: seq[Opt[FieldElement]]): bool =
  for i, ring in rings:
    if ring.currentPublicKey() == first[i]:
      return false
  true

suite "Mix Protocol - Key Rotation":
  asyncTeardown:
    checkTrackers()

  asyncTest "the local record carries the ring's current key":
    let (nodes, rings) = setupKeyRotationNodes(1, config = fastRotationConfig())
    let first = rings[0].currentPublicKey().expect("first key")
    check nodes[0].localMixPubInfo().expect("local mix info").mixPubKey == first
    startAndDeferStop(nodes)

    checkUntilTimeout:
      rings[0].currentPublicKey() != Opt.some(first)
    check nodes[0].localMixPubInfo().expect("local mix info").mixPubKey ==
      rings[0].currentPublicKey().expect("current key")

  test "the local record is unavailable while the ring holds no key":
    let mixNodeInfo = MixNodeInfo.generateRandom(4300, rng())
    let node = MixProtocol.new(
      mixNodeInfo,
      createSwitch(mixNodeInfo.multiAddr, Opt.some(mixNodeInfo.libp2pPrivKey)),
      keyRing = Opt.some(
        MixKeyRing.new(
          KeyRotationConfig.init().expect("default config"),
          rng(),
          replayTableCapacity = 16,
        )
      ),
    )
    check node.localMixPubInfo().isErr

  asyncTest "a message reaches its destination through rotating nodes":
    let (nodes, _) = setupKeyRotationNodes(10)
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    let conn = nodes[0].toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    let data = @[1.byte, 2, 3, 4, 5]
    await conn.writeLp(data)
    await conn.close()

    let receivedMsg = await nrProto.receivedMessages.get().wait(2.seconds)
    check receivedMsg.data == data

  asyncTest "a reply returns through a SURB to a rotating sender":
    let (nodes, _) = setupKeyRotationNodes(
      10, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )
    startAndDeferStop(nodes)

    let (destNode, pingProto) = await setupDestNode(Ping.new(rng = rng()))
    defer:
      await stopDestNode(destNode)

    let conn = nodes[0]
      .toConnection(
        destNode.toMixDestination(),
        pingProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
      )
      .expect("could not build connection")

    let response = await pingProto.ping(conn)
    await conn.close()

    check response != 0.seconds

  asyncTest "a packet built for a replaced key is delivered in the grace window":
    let (nodes, rings) = setupKeyRotationNodes(10, config = fastRotationConfig())
    let first = rings.firstKeys()
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    # Every pool still holds the first keys, which the hops accept only in their
    # grace windows once they rotate.
    checkUntilTimeout:
      rings.allRotated(first)

    let conn = nodes[0].toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    let data = @[1.byte, 2, 3, 4, 5]
    await conn.writeLp(data)
    await conn.close()

    let receivedMsg = await nrProto.receivedMessages.get().wait(2.seconds)
    check receivedMsg.data == data

  asyncTest "a packet built for a destroyed key is dropped":
    let (nodes, rings) = setupKeyRotationNodes(10, config = fastRotationConfig())
    let firstKeys = rings.mapIt(it.candidates()[0])
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)

    # Every pool still holds the first keys, which the hops have destroyed.
    checkUntilTimeout:
      firstKeys.allIt(it.isDestroyed)

    let conn = nodes[0].toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    await conn.writeLp(@[1.byte, 2, 3, 4, 5])
    await conn.close()

    # A dropped packet gives no signal, so wait a bounded time for one that must
    # not arrive.
    check not await nrProto.receivedMessages.get().withTimeout(1.seconds)
