# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/[switch, multiaddress, crypto/secp, peerid]
import libp2p_mix
import libp2p_mix/[mix_protocol, delay_strategy]
import ../tools/[lifecycle, unittest, crypto, host_pool]
import ../utils

suite "A host pool in real exchanges":
  asyncTeardown:
    checkTrackers()

  asyncTest "a host pool supports requests, replies and cover":
    let nodes = await startTestMixNodes(5)
    defer:
      await stopNodes(nodes)
    let echo = EchoProtocol.new()
    await echo.start()
    nodes[^1].switch.mount(echo)
    for node in nodes:
      node.registerDestReadBehavior(echo.codec, readLp(1024))
    for fixedExit in [false, true]:
      let destination =
        if fixedExit:
          MixDestination.exitNode(nodes[^1].localMixPubInfo().peerId)
        else:
          nodes[^1].switch.toMixDestination()
      let conn = nodes[0]
        .toConnection(
          destination,
          echo.codec,
          MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8)),
        )
        .get()
      try:
        await conn.writeLp(@[1'u8, 2, 3]).wait(5.seconds)
        check (await conn.readLp(1024).wait(5.seconds)) == @[1'u8, 2, 3]
      finally:
        await conn.close()
    check (await nodes[0].buildCoverPacket()).isOk
    check nodes[0].surbCredsLen == 0

  asyncTest "a failed entry dial keeps the host records":
    let closed = createSwitch()
    await closed.start()
    let closedAddress = closed.peerInfo.addrs[0]
    await closed.stop()
    let (other, receiver) = await setupDestNode(NoReplyProtocol.new())
    defer:
      await stopDestNode(other)
    let info = MixNodeInfo.generateRandom(0, rng())
    let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
    let pool = HostPool.new()
    for node in MixNodeInfo.generateRandomMany(3, rng()):
      var candidate = node.toMixPubInfo()
      candidate.multiAddr = closedAddress
      pool.addPeer(candidate)
    let sender = MixProtocol.new(
      info,
      sw,
      pool = pool,
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
    )
    sw.mount(sender)
    let nodes = @[sender]
    startAndDeferStop(nodes)
    let conn = sender.toConnection(other.toMixDestination(), receiver.codec).get()
    defer:
      await conn.close()
    expect LPStreamError:
      await conn.writeLp(@[1'u8, 2, 3]).wait(5.seconds)
    # The library does not change the host pool after a failed dial.
    check pool.listPeerIds().get().len == 3
