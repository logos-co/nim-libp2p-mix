# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Path requests shared by selection strategies, independent of packet
## construction and transport sessions.

import std/[sets, tables]
import results
import libp2p/peerid
import ./[mix_node, multiaddr, serialization, curve25519]

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
    if info.mixPubKey == default(FieldElement) or
        multiAddrToBytes(info.peerId, info.multiAddr).isErr:
      return err("unusable fixed hop")
    fixedIds.incl(info.peerId)
  ok()
