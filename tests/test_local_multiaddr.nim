# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sequtils
import libp2p/[multiaddress, peerid, switch]
import
  libp2p_mix/
    [mix_protocol, mix_node, sphinx, serialization, multiaddr, tag_manager, curve25519]
import ./tools/[unittest, crypto, lifecycle]
import ./utils

proc privKeyFor(infos: seq[MixNodeInfo], peerId: PeerId): FieldElement =
  for info in infos:
    if info.peerId == peerId:
      return info.mixPrivKey
  raiseAssert "no MixNodeInfo for peerId"

proc setupNodesWithInfos(
    count: int
): Future[tuple[nodes: seq[MixProtocol], infos: seq[MixNodeInfo]]] {.async.} =
  ## Like setupMixNodes, but also returns MixNodeInfo so tests can peel Sphinx hops.
  let infos = MixNodeInfo.generateRandomMany(count, rng())
  var nodes: seq[MixProtocol] = @[]
  for info in infos:
    let switch = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
    let proto = MixProtocol.new(info, switch)
    proto.nodePool.add(infos.includeAllExcept(info))
    switch.mount(proto)
    nodes.add(proto)
  (nodes, infos)

proc replacePool(mix: MixProtocol, keep: seq[MixPubInfo]) =
  for peerId in mix.nodePool.peerIds():
    discard mix.nodePool.remove(peerId)
  mix.nodePool.add(keep)

proc selfMultiAddrFromPath(
    packetBytes: seq[byte], firstHopPeerId: PeerId, infos: seq[MixNodeInfo]
): MultiAddress =
  ## Peel PathLength-1 intermediate hops. The penultimate hop's nextHop is the
  ## self/originator multiaddr embedded when the packet was built.
  var tm = TagManager.new(autoStart = false)
  defer:
    clearTags(tm)

  var packet = SphinxPacket.deserialize(packetBytes).expect("deserialize sphinx packet")
  var currentPeerId = firstHopPeerId

  for hopIdx in 0 ..< PathLength - 1:
    let processed = processSphinxPacket(packet, privKeyFor(infos, currentPeerId), tm)
      .expect("process intermediate hop")
    doAssert processed.status == Intermediate, "expected Intermediate hop"
    let (nextPeerId, nextMa) =
      bytesToMultiAddr(processed.nextHop.get()).expect("decode next hop")
    if hopIdx == PathLength - 2:
      return nextMa
    currentPeerId = nextPeerId
    packet = SphinxPacket.deserialize(processed.serializedSphinxPacket).expect(
        "deserialize forwarded packet"
      )

  raiseAssert "unreachable: path shorter than PathLength"

suite "setLocalMultiAddr":
  asyncTest "updates self multiaddr used by localMixPubInfo and SURB build":
    # +2 leaves PathLength-1 intermediates after excluding dest and exit.
    let (nodes, infos) = await setupNodesWithInfos(PathLength + 2)
    startAndDeferStop(nodes)

    let mix = nodes[0]
    let original = mix.localMixPubInfo().multiAddr
    let updated = MultiAddress.init("/ip4/203.0.113.10/tcp/9000").tryGet()

    check mix.setLocalMultiAddr(updated).isOk
    check mix.localMixPubInfo().multiAddr == updated
    check mix.localMixPubInfo().multiAddr != original

    # Force the SURB intermediate path onto infos[3] and infos[4] so we can
    # peel Sphinx layers with known private keys. Pool must still have
    # PathLength entries (exit is filtered out by buildSurb).
    let destInfo = infos[1]
    let exitInfo = infos[2]
    replacePool(
      mix, @[infos[3].toMixPubInfo(), infos[4].toMixPubInfo(), exitInfo.toMixPubInfo()]
    )

    var id: SURBIdentifier
    rng().generate(id)
    let surb = mix.buildSurb(id, destInfo.peerId, exitInfo.peerId).expect("build SURB")

    let firstHopPeerId =
      bytesToMultiAddr(surb.hop.get()).expect("decode SURB first hop")[0]
    let packetBytes = useSURB(surb, newSeq[byte](MessageSize)).serialize()
    let selfMa = selfMultiAddrFromPath(packetBytes, firstHopPeerId, infos)

    check selfMa == updated

  asyncTest "rejects multiaddrs that cannot be encoded as a mix hop":
    let nodes = await setupMixNodes(1)
    startAndDeferStop(nodes)

    let mix = nodes[0]
    let before = mix.localMixPubInfo().multiAddr

    # Missing transport (ip4 only)
    let noTransport = MultiAddress.init("/ip4/203.0.113.10").tryGet()
    check mix.setLocalMultiAddr(noTransport).isErr
    check mix.localMixPubInfo().multiAddr == before

    # Trailing destination /p2p/<peerId> is not a mix-encodable hop address
    let withP2p = MultiAddress
      .init("/ip4/203.0.113.10/tcp/9000/p2p/" & $mix.localMixPubInfo().peerId)
      .tryGet()
    check mix.setLocalMultiAddr(withP2p).isErr
    check mix.localMixPubInfo().multiAddr == before

  asyncTest "cover packet build uses updated self multiaddr":
    let (nodes, infos) = await setupNodesWithInfos(PathLength + 1)
    startAndDeferStop(nodes)

    let mix = nodes[0]
    let updated = MultiAddress.init("/ip4/198.51.100.5/tcp/4242").tryGet()
    check mix.setLocalMultiAddr(updated).isOk

    # Force intermediates onto a known PathLength-1 subset.
    replacePool(mix, infos[1 .. PathLength - 1].mapIt(it.toMixPubInfo()))

    let built = mix.buildCoverPacket().expect("build cover packet")
    let selfMa = selfMultiAddrFromPath(built.packet, built.firstHopPeerId, infos)

    check selfMa == updated
