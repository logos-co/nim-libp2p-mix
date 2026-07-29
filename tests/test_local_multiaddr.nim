# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/multiaddress
import libp2p/crypto/crypto
import libp2p_mix
import libp2p_mix/[mix_protocol, sphinx, serialization]
import ./tools/[unittest, crypto, lifecycle]
import ./utils

suite "setLocalMultiAddr":
  asyncTest "updates self multiaddr used by localMixPubInfo and SURB build":
    # +2 leaves PathLength-1 intermediates after excluding dest and exit.
    let nodes = await setupMixNodes(PathLength + 2)
    startAndDeferStop(nodes)

    let mix = nodes[0]
    let original = mix.localMixPubInfo().multiAddr
    let updated = MultiAddress.init("/ip4/203.0.113.10/tcp/9000").tryGet()

    check mix.setLocalMultiAddr(updated).isOk
    check mix.localMixPubInfo().multiAddr == updated
    check mix.localMixPubInfo().multiAddr != original

    var id: SURBIdentifier
    rng().generate(id)
    let surb = mix.buildSurb(
      id, nodes[1].localMixPubInfo().peerId, nodes[2].localMixPubInfo().peerId
    )
    check surb.isOk

  asyncTest "rejects multiaddrs that cannot be encoded as a mix hop":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)

    let mix = nodes[0]
    let before = mix.localMixPubInfo().multiAddr
    let invalid = MultiAddress.init("/ip4/203.0.113.10").tryGet()

    check mix.setLocalMultiAddr(invalid).isErr
    check mix.localMixPubInfo().multiAddr == before

  asyncTest "cover packet build uses updated self multiaddr":
    let nodes = await setupMixNodes(PathLength + 1)
    startAndDeferStop(nodes)

    let mix = nodes[0]
    let updated = MultiAddress.init("/ip4/198.51.100.5/tcp/4242").tryGet()
    check mix.setLocalMultiAddr(updated).isOk

    let built = mix.buildCoverPacket()
    check built.isOk
