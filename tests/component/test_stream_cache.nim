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
