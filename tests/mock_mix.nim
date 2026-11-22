# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sets, sequtils
import libp2p/[crypto/curve25519, peerid, peerstore, switch, stream/lpstream]
import libp2p_mix
import libp2p_mix/mix_protocol
import libp2p_mix/pool
import libp2p_mix/serialization
import libp2p_mix/sphinx

type MockMixProtocol* = ref object of MixProtocol
  surbCallIndex: int
  surbPeerSets*: seq[seq[PeerId]]
  ## Forces each SURB onto a known path by temporarily narrowing the node pool
  ## before delegating to the real buildSurb.
  ##
  ## Usage:
  ##   mock.surbPeerSets = @[
  ##     @[nodeA, nodeB, nodeC],   # candidates for SURB 0
  ##     @[nodeD, nodeE, nodeF],   # candidates for SURB 1
  ##   ]
  ## Each default three-hop SURB reply path needs exactly 2 intermediary nodes.
  ## buildSurb filters out the exit, so provide at least pathLength candidates
  ## when the exit might be among them.
  ##
  ## After the message is sent, mock.actualSurbPeers records which relays were
  ## selected for each SURB, so tests can target specific nodes.
  actualSurbPeers*: seq[seq[PeerId]]
  ## Incoming raw bytes in handleMixMessages are captured here
  capturedBytes*: seq[byte]
  ## Count of packets received via handleMixMessages
  receivedPacketCount*: int

method buildSurb*(
    mock: MockMixProtocol, id: SURBIdentifier, destPeerId: PeerId, exitPeerId: PeerId,
    selector: PathSelector = nil,
    pathLength: int = DefaultPathLength,
): Result[SurbBuild, string] {.gcsafe, raises: [].} =
  # No forced paths configured or all sets consumed: use the supplied/default selector.
  if mock.surbPeerSets.len == 0 or mock.surbCallIndex >= mock.surbPeerSets.len:
    return procCall buildSurb(MixProtocol(mock), id, destPeerId, exitPeerId, selector, pathLength)

  # The exit node is randomly chosen during forward path construction, so it
  # might be one of our candidates. Remove it.
  let candidates = mock.surbPeerSets[mock.surbCallIndex].filterIt(it != exitPeerId)
  doAssert pathLength >= MinPathLength and pathLength <= MaxPathLength
  doAssert candidates.len >= pathLength - 1
  let peers = candidates[0 ..< pathLength - 1]

  # Keep the desired relays plus the exit, which selection excludes.
  let keepInPool = (peers & exitPeerId).toHashSet()

  # `remove` deletes only the mix key, so the mix key is what comes back. A
  # member with no hop address has no MixPubInfo to keep.
  let mixKeys = mock.switch.peerStore[MixPubKeyBook]
  var removed: seq[(PeerId, Curve25519Key)]
  for peerId in mock.nodePool.peerIds():
    if peerId notin keepInPool:
      removed.add((peerId, mixKeys[peerId]))
      discard mock.nodePool.remove(peerId)

  let surb = procCall buildSurb(MixProtocol(mock), id, destPeerId, exitPeerId, selector, pathLength)

  for (peerId, mixPubKey) in removed:
    mixKeys[peerId] = mixPubKey

  mock.actualSurbPeers.add(peers)
  mock.surbCallIndex.inc
  surb

method handleMixMessages*(
    mock: MockMixProtocol,
    fromPeerId: PeerId,
    receivedBytes: sink seq[byte],
    metadataBytes: sink seq[byte],
) {.async: (raises: [LPStreamError, CancelledError]).} =
  mock.capturedBytes = @receivedBytes
  mock.receivedPacketCount.inc

  await procCall handleMixMessages(
    MixProtocol(mock), fromPeerId, receivedBytes, metadataBytes
  )
