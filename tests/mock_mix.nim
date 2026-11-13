# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results, sets, sequtils
import libp2p/[crypto/curve25519, peerid, peerstore, switch, stream/lpstream]
import libp2p_mix
import libp2p_mix/mix_protocol
import libp2p_mix/pool
import libp2p_mix/serialization

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
  ## Each SURB reply path needs exactly 2 intermediary nodes. buildSurb filters
  ## out the exit node from candidates, so if the exit happens to be one of the candidates,
  ## there would be too few. Provide 3+ to be safe.
  ##
  ## After the message is sent, mock.actualSurbPeers records which 2 peers were
  ## selected for each SURB, so tests can target specific nodes.
  actualSurbPeers*: seq[seq[PeerId]]
  ## Incoming raw bytes in handleMixMessages are captured here
  capturedBytes*: seq[byte]
  ## Count of packets received via handleMixMessages
  receivedPacketCount*: int

method buildSurb*(
    mock: MockMixProtocol, id: SURBIdentifier, destPeerId: PeerId, exitPeerId: PeerId
): Result[SURB, string] {.gcsafe, raises: [].} =
  # No forced paths configured or all sets consumed — fall back to random selection
  if mock.surbPeerSets.len == 0 or mock.surbCallIndex >= mock.surbPeerSets.len:
    return procCall buildSurb(MixProtocol(mock), id, destPeerId, exitPeerId)

  # The exit node is randomly chosen during forward path construction, so it
  # might be one of our candidates. Remove it.
  let candidates = mock.surbPeerSets[mock.surbCallIndex].filterIt(it != exitPeerId)
  doAssert candidates.len >= 2
  let peers = candidates[0 .. 1]

  # buildSurb removes the exit and the destination, and it needs PathLength - 1
  # other nodes. We keep our 2 desired peers + the exit node, so it draws
  # exactly our 2.
  let keepInPool = (peers & exitPeerId).toHashSet()

  # `remove` deletes only the mix key, so the mix key is what comes back. A
  # member with no hop address has no MixPubInfo to keep.
  let mixKeys = mock.switch.peerStore[MixPubKeyBook]
  var removed: seq[(PeerId, Curve25519Key)]
  for peerId in mock.nodePool.peerIds():
    if peerId notin keepInPool:
      removed.add((peerId, mixKeys[peerId]))
      discard mock.nodePool.remove(peerId)

  let surb = procCall buildSurb(MixProtocol(mock), id, destPeerId, exitPeerId)

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
