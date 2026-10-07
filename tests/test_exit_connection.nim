# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import libp2p_mix/[exit_connection, serialization]
import ./tools/unittest

suite "MixExitConnection":
  test "received SURBs can be taken once by a protocol handler":
    let conn = MixExitConnection.new(@[1.byte], @[SURB(key: @[2.byte])])

    let surbs = conn.takeSURBs()
    check:
      surbs.len == 1
      surbs[0].key == @[2.byte]
      conn.takeSURBs().len == 0
