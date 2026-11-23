# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Session candidate identities and path selection relative to the initiator.

import std/[sets, tables, algorithm]
import results
import libp2p/peerid
import libp2p/crypto/rng
import ./[path_selection, mix_node, serialization, pool]

type SessionSelectorParams* = object
  ## All fields are required; these parameters are copied at construction.
  pathLength*: int
  hopCount*: int
    ## Number of session candidate sets, separate from caller-fixed hops.
  candidatesPerHop*: int

type SessionProfile* {.pure.} = enum
  Lite
  Standard
  Strict

func params*(profile: SessionProfile): SessionSelectorParams =
  ## Presets only: construction initializes private state once per session.
  ## Profiles do not change the default random selector used by Mix.
  case profile
  of SessionProfile.Lite:
    SessionSelectorParams(pathLength: 3, hopCount: 1, candidatesPerHop: 5)
  of SessionProfile.Standard:
    SessionSelectorParams(pathLength: 3, hopCount: 2, candidatesPerHop: 5)
  of SessionProfile.Strict:
    SessionSelectorParams(pathLength: 4, hopCount: 3, candidatesPerHop: 3)

type SessionPathState = object
  ## Sets are ordered from the initiator outward and stay fixed for the session.
  ## Each set controls one relay position, separate from caller-fixed hops.
  candidateSets: seq[seq[PeerId]]

proc init(
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

proc sampleSessionState(
    candidates: openArray[MixPubInfo], rng: Rng, hopCount, candidatesPerHop: int
): Result[SessionPathState, string] =
  ## Inputs are validated by the constructor; resolved identities are distinct.
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

type SessionPathSelector* = ref object of PathSelector
  state: SessionPathState
  rng: Rng
  length: int

method pathLength*(selector: SessionPathSelector): int {.gcsafe, raises: [].} =
  selector.length

proc validateInputs(
    nodePool: MixNodePool, rng: Rng, pathLength: int
): Result[void, string] =
  ?validatePathLength(pathLength)
  if nodePool.isNil:
    return err("missing mix node pool")
  if rng.isNil:
    return err("missing CSPRNG")
  ok()

proc new*(
    T: typedesc[SessionPathSelector], nodePool: MixNodePool, rng: Rng,
    params: SessionSelectorParams,
): Result[T, string] =
  ## Initialize once from currently usable pool nodes. State stays private
  ## and fixed for this session; request failures never replenish its sets.
  ?validateInputs(nodePool, rng, params.pathLength)
  if params.hopCount < 1 or params.hopCount > params.pathLength:
    return err("unsupported session hop count")
  if params.candidatesPerHop < 1:
    return err("session candidate count must be positive")
  let candidates = resolveCandidates(nodePool, nodePool.peerIds(), default(HashSet[PeerId]))
  let state = ?sampleSessionState(candidates, rng, params.hopCount, params.candidatesPerHop)
  ok(T(nodePool: nodePool, rng: rng, state: state, length: params.pathLength))

proc new*(
    T: typedesc[SessionPathSelector], nodePool: MixNodePool, rng: Rng,
    candidateSets: openArray[seq[PeerId]], pathLength: int = DefaultPathLength,
): Result[T, string] =
  ## Advanced construction: preserve supplied identities, grouping and order.
  ## Metadata is resolved when selecting paths, so unavailable IDs are allowed.
  ?validateInputs(nodePool, rng, pathLength)
  let state = ?SessionPathState.init(candidateSets)
  if state.candidateSets.len > pathLength:
    return err("unsupported session hop count")
  ok(T(nodePool: nodePool, rng: rng, state: state, length: pathLength))

method samplePath*(
    selector: SessionPathSelector, request: PathRequest
): Result[MixPath, string] {.gcsafe, raises: [].} =
  ## selectPath validates the request and the completed path around this method.
  if request.purpose == PathPurpose.Cover:
    return err("session selector does not support cover paths")
  if selector.rng.isNil:
    return err("missing CSPRNG")
  if selector.state.candidateSets.len == 0:
    return err("empty session path state")

  var (path, excludedIds) = prepareFixedHops(request, selector.pathLength)
  var positions: seq[int]
  for position in 0 ..< path.len:
    if not request.constraints.fixedHops.hasKey(position):
      positions.add(position)
  let sessionHops = selector.state.candidateSets.len
  if positions.len < sessionHops:
    return err("not enough unfilled positions for session candidate sets")
  if request.purpose == PathPurpose.Surb:
    positions.reverse()

  for index, ids in selector.state.candidateSets:
    let candidates = resolveCandidates(selector.nodePool, ids, excludedIds)
    if candidates.len == 0:
      return err("no usable candidates in session set for this request")
    let node = (?pickRandomNodes(selector.rng, candidates, 1))[0]
    path[positions[index]] = node
    excludedIds.incl(node.peerId)

  let randomHops = positions.len - sessionHops
  if randomHops > 0:
    let candidates = resolveCandidates(
      selector.nodePool, selector.nodePool.peerIds(), excludedIds
    )
    let sampled = ?pickRandomNodes(selector.rng, candidates, randomHops)
    for index, node in sampled:
      path[positions[sessionHops + index]] = node
  ok(path)
