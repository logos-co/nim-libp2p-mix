# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

from std/times import getTime
import chronos, results, sequtils
import libp2p/[protocols/ping, switch]
import libp2p_mix
import libp2p_mix/[delay_strategy, key_rotation, mix_protocol]

import ../tools/[lifecycle, unittest, crypto]
import ../utils

proc setupKeyRotationNodes(
    numNodes: int,
    destReadBehavior = Opt.none(tuple[codec: string, callback: DestReadBehavior]),
    schedule = KeySchedule.init().expect("default schedule"),
): seq[MixProtocol] =
  ## Nodes that each rotate their mix key. Each pool holds the key every other
  ## node uses in the current key period.
  var
    nodes: seq[MixProtocol]
    infos: seq[MixPubInfo]
  for mixNodeInfo in MixNodeInfo.generateRandomMany(numNodes, rng()):
    let ring = MixKeyRing.new(
      schedule,
      rng(),
      replayTableCapacity = 1024,
      publishedThrough = Opt.none(KeyPeriod),
    )
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
    infos.add(info)

  for index, node in nodes:
    node.nodePool.add(infos.filterIt(it.peerId != infos[index].peerId))
  nodes

suite "Mix Protocol - Key Rotation":
  asyncTeardown:
    checkTrackers()

  asyncTest "a message reaches its destination through rotating nodes":
    let nodes = setupKeyRotationNodes(10)
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
    let nodes = setupKeyRotationNodes(
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

  asyncTest "a packet built for the previous key is delivered in the grace window":
    let schedule = KeySchedule
      .init(
        periodDuration = 4.seconds,
        earlyWindow = 100.milliseconds,
        graceWindow = 2.seconds,
        maxClockOffset = ZeroDuration,
        maxTransit = 100.milliseconds,
      )
      .expect("fast schedule")

    # Start at the beginning of a key period, so every pool holds keys for it.
    let before = schedule.keyPeriod(getTime())
    checkUntilTimeout:
      schedule.keyPeriod(getTime()) > before
    let period = schedule.keyPeriod(getTime())

    let nodes = setupKeyRotationNodes(10, schedule = schedule)
    startAndDeferStop(nodes)

    let (destNode, nrProto) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(destNode)
    check schedule.keyPeriod(getTime()) == period # setup finished within the period

    # Every hop now has a newer current key and accepts the pooled one only in
    # its grace window.
    checkUntilTimeout:
      schedule.keyPeriod(getTime()) > period

    let conn = nodes[0].toConnection(destNode.toMixDestination(), nrProto.codec).expect(
        "could not build connection"
      )
    let data = @[1.byte, 2, 3, 4, 5]
    await conn.writeLp(data)
    await conn.close()

    let receivedMsg = await nrProto.receivedMessages.get().wait(2.seconds)
    check:
      schedule.keyPeriod(getTime()) == period + 1
      receivedMsg.data == data
