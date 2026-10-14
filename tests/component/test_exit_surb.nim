# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Logos

{.used.}

import std/tables
import chronos
import libp2p/[builders, switch]
import libp2p/protocols/protocol
import libp2p/stream/connection
import libp2p_mix/[exit_layer, exit_connection, serialization]
import ../tools/unittest

when defined(libp2p_mix_experimental_exit_is_dest):
  suite "Exit SURB ownership":
    asyncTest "automatic replies only use unclaimed SURBs":
      for (claim, writeResponse) in [(false, true), (true, true), (false, false)]:
        var replies = 0
        var response: seq[byte]
        let sw = SwitchBuilder.new().withTcpTransport().withMplex().withNoise().build()
        let layer = ExitLayer.init(
          sw,
          proc(surb: SURB, message: seq[byte]) {.async: (raises: [CancelledError]).} =
            inc replies
            response = message,
          newTable[string, DestReadBehavior](),
        )
        sw.mount(
          LPProtocol.new(
            codecs = @["/mix/test/surb-ownership"],
            handler = proc(
                conn: Connection, proto: string
            ) {.async: (raises: [CancelledError]).} =
              if claim:
                check MixExitConnection(conn).takeSURBs().len == 1
              if writeResponse:
                try:
                  await conn.write(@[3.byte])
                except LPStreamError:
                  check false
            ,
          )
        )
        await layer.onMessage(
          "/mix/test/surb-ownership", @[1.byte], Hop(), @[SURB(key: @[2.byte])]
        )
        check replies == (if claim: 0 else: 1)
        if not claim:
          check response == (if writeResponse: @[3.byte]
          else: newSeq[byte]())
        await sw.stop()

    asyncTest "handler cancellation propagates":
      const Codec = "/mix/test/cancellation"
      let
        sw = SwitchBuilder.new().withTcpTransport().withMplex().withNoise().build()
        handlerStarted = newAsyncEvent()
        handlerGate = newAsyncEvent()
        layer = ExitLayer.init(
          sw,
          proc(surb: SURB, message: seq[byte]) {.async: (raises: [CancelledError]).} =
            discard,
          newTable[string, DestReadBehavior](),
        )
      defer:
        await sw.stop()

      var handlerCancelled = false
      sw.mount(
        LPProtocol.new(
          codecs = @[Codec],
          handler = proc(
              conn: Connection, proto: string
          ) {.async: (raises: [CancelledError]).} =
            handlerStarted.fire()
            try:
              await handlerGate.wait()
            except CancelledError as exc:
              handlerCancelled = true
              raise exc,
        )
      )

      let messageFut = layer.onMessage(Codec, @[1.byte], Hop(), @[])
      await handlerStarted.wait().wait(1.seconds)
      await messageFut.cancelAndWait()

      check:
        handlerCancelled
        messageFut.cancelled()
