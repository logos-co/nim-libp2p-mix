# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Shared requests and validation for path selection strategies, independent
## of packet construction and transport sessions.

import std/[sets, tables]
import results
import libp2p/[peerid, multiaddress]
import libp2p/crypto/secp
import libp2p/crypto/rng
import ./[mix_node, multiaddr, serialization, curve25519, pool]

type
  PathPurpose* {.pure.} = enum
    Forward
    Surb
    Cover

  PathConstraints* = object
    excludedNodeIds*: HashSet[PeerId]
      ## Exclusions apply to sampled hops, not explicitly fixed hops.
    fixedHops*: Table[int, MixPubInfo]
      ## Zero-based positions in packet traversal order. Explicit endpoints
      ## need not belong to the relay pool.

  PathRequest* = object
    purpose*: PathPurpose
      ## Context for the strategy; callers supply purpose-specific constraints.
    pathLength*: int
      ## Total mix hops, including fixed hops. Must be specified explicitly.
    constraints*: PathConstraints

  MixPath* = seq[MixPubInfo]

  PathSelector* = ref object of RootObj
    nodePool*: MixNodePool
      ## Shared pool reference, not a copy. Strategies read current node data
      ## without modifying the pool.

  RandomPathSelector* = ref object of PathSelector
    rng: Rng

proc hasRoutingInfo(info: MixPubInfo): bool =
  info.mixPubKey != default(FieldElement) and
    multiAddrToBytes(info.peerId, info.multiAddr).isOk

proc validatePathRequest*(request: PathRequest): Result[void, string] =
  ## Validate before selecting any nodes. This checks request structure and
  ## fixed-hop encoding requirements, not liveness or reputation eligibility.
  if request.pathLength < MinPathLength or request.pathLength > MaxPathLength:
    return err("unsupported path length")

  var fixedIds: HashSet[PeerId]
  for position, info in request.constraints.fixedHops:
    if position < 0 or position >= request.pathLength:
      return err("fixed hop index outside path")
    if info.peerId in fixedIds:
      return err("duplicate fixed hop identity")
    if not hasRoutingInfo(info):
      return err("unusable fixed hop")
    fixedIds.incl(info.peerId)
  ok()

method samplePath*(
    selector: PathSelector, request: PathRequest
): Result[MixPath, string] {.base, gcsafe, raises: [].} =
  ## Here is where the path selection strategy does it's job: 
  ## - Apply path request constraints
  ## - Fill-in the rest of the mix nodes in the path based on the strategy and the current pool state
  ## - return an error if it is not possible to fulfil the request
  ## The request is not validated here.
  err("path selector is not implemented")

proc new*(T: typedesc[RandomPathSelector], nodePool: MixNodePool, rng: Rng): T =
  doAssert not rng.isNil, "path selection requires a CSPRNG"
  T(nodePool: nodePool, rng: rng)

proc prepareFixedHops(
    request: PathRequest
): tuple[path: MixPath, excludedIds: HashSet[PeerId]] =
  ## The request has already been validated by selectPath.
  ## Reserve every fixed identity before sampling any unfilled position.
  result.path = newSeq[MixPubInfo](request.pathLength)
  result.excludedIds = request.constraints.excludedNodeIds
  for position, info in request.constraints.fixedHops:
    result.path[position] = info
    result.excludedIds.incl(info.peerId)

proc resolveCandidates(
    pool: MixNodePool, candidateIds: openArray[PeerId], excludedIds: HashSet[PeerId]
): seq[MixPubInfo] =
  ## The strategy supplies distinct identities: the whole pool for random
  ## selection, or a stored candidate set for a future session strategy.
  ## Resolve current routing information without changing pool membership.
  for peerId in candidateIds:
    if peerId in excludedIds:
      continue
    let info = pool.get(peerId).valueOr:
      continue
    if hasRoutingInfo(info):
      result.add(info)

proc pickRandomNodes(
    rng: Rng, candidates: openArray[MixPubInfo], count: int
): Result[MixPath, string] =
  ## Pick exactly count nodes without replacement from filtered, distinct candidates.
  ## The caller supplies a non-nil RNG and a non-negative count.
  if count == 0:
    return ok(newSeq[MixPubInfo]())
  if candidates.len < count:
    return err("not enough usable mix nodes")
  if uint64(candidates.len) > uint64(high(uint32)):
    return err("candidate pool too large")
  let sampled = rng.pick(candidates, count).valueOr:
    return err("not enough usable mix nodes")
  ok(sampled)

method samplePath*(
    selector: RandomPathSelector, request: PathRequest
): Result[MixPath, string] {.gcsafe, raises: [].} =
  if selector.rng.isNil:
    return err("missing CSPRNG")

  var (path, excludedIds) = prepareFixedHops(request)
  let count = request.pathLength - request.constraints.fixedHops.len
  if count == 0:
    return ok(path)

  let candidates = resolveCandidates(
    selector.nodePool, selector.nodePool.peerIds(), excludedIds
  )
  let sampled = ?pickRandomNodes(selector.rng, candidates, count)
  var next = 0
  for position in 0 ..< path.len:
    if not request.constraints.fixedHops.hasKey(position):
      path[position] = sampled[next]
      inc next
  ok(path)

proc selectPath*(
    selector: PathSelector, request: PathRequest
): Result[MixPath, string] {.gcsafe, raises: [].} =
  
  if selector.isNil or selector.nodePool.isNil:
    return err("missing selector or pool")
  ?request.validatePathRequest()

  ## call the path selector and validate the returned path.
  let path = ?selector.samplePath(request)
  if path.len != request.pathLength:
    return err("selector returned wrong path length")
  var used: HashSet[PeerId]
  for position, info in path:
    if info.peerId in used:
      return err("selector repeated a node")
    used.incl(info.peerId)
    if request.constraints.fixedHops.hasKey(position):
      if info != request.constraints.fixedHops.getOrDefault(position):
        return err("selector changed a fixed hop")
    else:
      if info.peerId in request.constraints.excludedNodeIds:
        return err("selector returned an excluded node")
      let current = selector.nodePool.get(info.peerId).valueOr:
        return err("selector returned a node without usable pool information")
      if not hasRoutingInfo(current):
        return err("selector returned a node without usable pool information")
      if current != info:
        return err("selector returned stale or altered node information")
  ok(path)
