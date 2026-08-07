# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/protocols/protocol
import libp2p_mix
import libp2p_mix/mix_protocol
import ./tools/[unittest, crypto]
import ./utils

suite "MixProtocol stream budget":
  test "MixProtocol.new passes the budget to LPProtocol":
    # `LPProtocol` installs its budget only in `LPProtocol.new`. Building with
    # `new(T)` leaves it nil and silently accepts every stream, and with the
    # defaults unlimited nothing else would notice the regression.
    let
      info = MixNodeInfo.generateRandomMany(1, rng())[0]
      switch = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
      proto = MixProtocol.new(info, switch, maxIncomingStreamsPerPeer = Opt.some(1))
      peer = switch.peerInfo.peerId

    check proto.reserveIncoming(peer)
    check not proto.reserveIncoming(peer)
