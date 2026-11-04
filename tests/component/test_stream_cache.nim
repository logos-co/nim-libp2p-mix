# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos, metrics, results
import libp2p/[switch, peerid, multiaddress]
import libp2p_mix
import libp2p_mix/[mix_protocol, mix_metrics]
import ../tools/[lifecycle, unittest, crypto]
import ../utils

proc errorCount(role, reason: string): float64 =
  ## The count of `mix_messages_error` for `role` and `reason`. 0 before the
  ## label exists.
  try:
    mix_messages_error.value([role, reason])
  except KeyError:
    0.0

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

  asyncTest "protocol stop cancels a dial in flight and refuses a new dial":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)

    # A server that accepts and never answers keeps a dial in its handshake.
    var connections: seq[StreamTransport]
    let server = createStreamServer(initTAddress("127.0.0.1:0"))
    proc acceptLoop() {.async.} =
      while true:
        connections.add(await server.accept())

    let acceptor = acceptLoop()
    defer:
      await acceptor.cancelAndWait()
      for connection in connections:
        await connection.closeWait()
      await server.closeWait()

    let hopPeerId = PeerId.random(rng()).expect("peer id")
    let hopAddr = MultiAddress.init(server.localAddress()).expect("address")
    let sending = nodes[0].sendCoverPacket(hopPeerId, hopAddr, @[1.byte])
    checkUntilTimeout:
      connections.len == 1
    check not sending.finished

    await nodes[0].stop()
    expect CancelledError:
      discard await sending.wait(2.seconds)
    # A refusal by the stop is not a failure of the hop, so it counts nothing.
    let errorsBefore = errorCount("Cover", "SEND_FAILED")
    let refused = await nodes[0].sendCoverPacket(hopPeerId, hopAddr, @[1.byte])
    check:
      refused.isErr
      errorCount("Cover", "SEND_FAILED") == errorsBefore
      connections.len == 1

    await nodes[0].start()
    let again = nodes[0].sendCoverPacket(hopPeerId, hopAddr, @[1.byte])
    checkUntilTimeout:
      connections.len == 2
    await again.cancelAndWait()
