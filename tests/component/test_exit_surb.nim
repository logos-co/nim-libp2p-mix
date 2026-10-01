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
      for claim in [false, true]:
        var replies = 0
        let sw = SwitchBuilder.new().withTcpTransport().withMplex().withNoise().build()
        let layer = ExitLayer.init(
          sw,
          proc(surb: SURB, message: seq[byte]) {.async: (raises: [CancelledError]).} =
            inc replies
          ,
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
        await sw.stop()
