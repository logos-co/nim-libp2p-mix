# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos, results
import libp2p/switch
import libp2p_mix
import libp2p_mix/mix_protocol
import ../tools/[lifecycle, unittest]
import ../utils

const ReplyParams = MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8))

proc exchange(
    sender: MixProtocol, destination: MixDestination, codec: string, value: byte
) {.async.} =
  let conn = sender.toConnection(destination, codec, ReplyParams).get()
  defer:
    await conn.close()
  await conn.writeLp(@[value]).wait(5.seconds)
  check (await conn.readLp(1024).wait(5.seconds)) == @[value]

suite "Hop stream cache":
  asyncTeardown:
    checkTrackers()

  asyncTest "concurrent requests and retries reuse one cached stream per peer":
    let nodes = await startTestMixNodes(5)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let echo = EchoProtocol.new()
    await echo.start()
    nodes[^1].switch.mount(echo)
    for node in nodes:
      node.registerDestReadBehavior(echo.codec, readLp(1024))
    for round in 0 .. 1:
      var pending: seq[Future[void]]
      for i in 0 ..< 8:
        let destination =
          if i mod 2 == 0:
            nodes[^1].switch.toMixDestination()
          else:
            MixDestination.exitNode(nodes[^1].localMixPubInfo().peerId)
        pending.add(exchange(sender, destination, echo.codec, i.byte))
      try:
        await allFutures(pending).wait(10.seconds)
        for request in pending:
          await request
      finally:
        await allFutures(pending.mapIt(it.cancelAndWait()))
      let streams = outgoingMixStreams(sender.switch)
      check streams.len > 0
      check streams.len <= sender.switch.connectedPeers().len
      check sender.surbCredsLen == 0
      if round == 0:
        # Close the cached streams and keep the cache entries, as a peer reset does.
        await allFutures(streams.mapIt(it.close()))
