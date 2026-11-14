# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Session candidate identities, independent of their source and routing metadata.
## Path sampling and forward/SURB position mapping will follow separately.

import std/sets
import results
import libp2p/peerid
import libp2p/crypto/rng
import ./[path_selection, mix_node, serialization]

type SessionPathState* = object
  ## Sets are ordered from the initiator outward and stay fixed for the session.
  ## Each set controls one relay position, separate from caller-fixed hops.
  candidateSets: seq[seq[PeerId]]

proc init*(
    T: typedesc[SessionPathState], candidateSets: openArray[seq[PeerId]]
): Result[T, string] =
  ## Validate structure and copy the supplied sets without regrouping them.
  ## Current metadata and request constraints are checked during path selection.
  if candidateSets.len < 1 or candidateSets.len > MaxPathLength:
    return err("unsupported session hop count")
  var
    state: T
    seen: HashSet[PeerId]
  for ids in candidateSets:
    if ids.len == 0:
      return err("session candidate sets must not be empty")
    var copied: seq[PeerId]
    for peerId in ids:
      if peerId in seen:
        return err("duplicate session candidate identity")
      seen.incl(peerId)
      copied.add(peerId)
    state.candidateSets.add(copied)
  ok(state)

proc candidateSets*(state: SessionPathState): seq[seq[PeerId]] =
  ## Return a value copy for inspection.
  state.candidateSets

proc sampleSessionState*(
    candidates: openArray[MixPubInfo], rng: Rng, hopCount, candidatesPerHop: int
): Result[SessionPathState, string] =
  ## Randomly form disjoint sets from already-filtered candidates. The caller
  ## chooses the source (e.g. the whole pool or trusted identities).
  if hopCount < 1 or hopCount > MaxPathLength:
    return err("unsupported session hop count")
  if candidatesPerHop < 1:
    return err("session candidate count must be positive")
  if rng.isNil:
    return err("missing CSPRNG")
  var seen: HashSet[PeerId]
  for candidate in candidates:
    if candidate.peerId in seen:
      return err("duplicate session candidate identity")
    seen.incl(candidate.peerId)
  # Check capacity before multiplication to avoid integer overflow.
  if candidatesPerHop > candidates.len div hopCount:
    return err("not enough usable mix nodes for session candidate sets")
  let sampled = ?pickRandomNodes(rng, candidates, hopCount * candidatesPerHop)
  var sets: seq[seq[PeerId]]
  for position in 0 ..< hopCount:
    var ids: seq[PeerId]
    for offset in 0 ..< candidatesPerHop:
      ids.add(sampled[position * candidatesPerHop + offset].peerId)
    sets.add(ids)
  SessionPathState.init(sets)
