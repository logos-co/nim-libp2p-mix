# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Logos

## Test switch muxer: `-d:mix_test_muxer=yamux` (default, yamux then mplex)
## or `mplex` (mplex only).

import libp2p/builders

const mixTestMuxer* {.strdefine: "mix_test_muxer".} = "yamux"

static:
  doAssert mixTestMuxer in ["yamux", "mplex"],
    "-d:mix_test_muxer must be yamux or mplex, got: " & mixTestMuxer

proc withTestMuxer*(b: SwitchBuilder): SwitchBuilder =
  when mixTestMuxer == "yamux":
    b.withYamux().withMplex()
  else:
    b.withMplex()
