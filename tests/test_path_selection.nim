# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sets, tables, sequtils]
import results
import libp2p/[multiaddress, peerstore, peerid]
import libp2p/crypto/secp
import libp2p_mix/[path_selection, mix_node, serialization, pool]
import ./tools/[unittest, crypto]

suite "Path request validation":
  var
    nodes: seq[MixPubInfo]
    request: PathRequest

  setup:
    nodes = MixNodeInfo.generateRandomMany(MaxPathLength, rng()).mapIt(it.toMixPubInfo())
    request = PathRequest(purpose: PathPurpose.Forward, pathLength: DefaultPathLength)

  test "all purposes accept supported lengths with no fixed hops":
    for purpose in PathPurpose:
      for length in MinPathLength .. MaxPathLength:
        request.purpose = purpose
        request.pathLength = length
        check request.validatePathRequest().isOk

  test "fixed hops may also be excluded from sampling":
    for purpose in PathPurpose:
      request.purpose = purpose
      request.constraints.fixedHops[request.pathLength - 1] = nodes[0]
      request.constraints.excludedNodeIds.incl(nodes[0].peerId)
      check request.validatePathRequest().isOk

  test "every position may be fixed when identities are distinct":
    request.pathLength = MaxPathLength
    for position, node in nodes:
      request.constraints.fixedHops[position] = node
    check request.validatePathRequest().isOk

  test "missing or unsupported lengths are rejected":
    check PathRequest().validatePathRequest().isErr
    for length in [-1, 0, 1, MinPathLength - 1, MaxPathLength + 1]:
      request.pathLength = length
      let outcome = request.validatePathRequest()
      require outcome.isErr
      check outcome.error == "unsupported path length"

  test "fixed positions must be within the requested path":
    for position in [-1, request.pathLength]:
      request.constraints.fixedHops[position] = nodes[0]
      let outcome = request.validatePathRequest()
      require outcome.isErr
      check outcome.error == "fixed hop index outside path"
      request.constraints.fixedHops.clear()

  test "fixed hops cannot repeat an identity even with different metadata":
    var duplicate = nodes[0]
    duplicate.multiAddr = nodes[1].multiAddr
    request.constraints.fixedHops[0] = nodes[0]
    request.constraints.fixedHops[1] = duplicate
    let outcome = request.validatePathRequest()
    require outcome.isErr
    check outcome.error == "duplicate fixed hop identity"

  test "fixed hops need a mix key and an encodable address":
    var invalid = nodes[0]
    invalid.mixPubKey = default(typeof(invalid.mixPubKey))
    request.constraints.fixedHops[0] = invalid
    let missingKey = request.validatePathRequest()
    require missingKey.isErr
    check missingKey.error == "unusable fixed hop"

    invalid = nodes[0]
    invalid.multiAddr = MultiAddress.init("/ip6/::1/tcp/4242").get()
    request.constraints.fixedHops[0] = invalid
    let unsupportedAddress = request.validatePathRequest()
    require unsupportedAddress.isErr
    check unsupportedAddress.error == "unusable fixed hop"

type SuppliedPathSelector = ref object of PathSelector
  path: MixPath
  calls: int
  failure: string

method samplePath(
    selector: SuppliedPathSelector, request: PathRequest
): Result[MixPath, string] {.gcsafe, raises: [].} =
  inc selector.calls
  if selector.failure.len > 0:
    return err(selector.failure)
  ok(selector.path)

type ResolvingPathSelector = ref object of PathSelector
  peerIds: seq[PeerId]

method samplePath(
    selector: ResolvingPathSelector, request: PathRequest
): Result[MixPath, string] {.gcsafe, raises: [].} =
  var path: MixPath
  for peerId in selector.peerIds:
    let info = selector.nodePool.get(peerId).valueOr:
      return err("stored candidate is unavailable")
    path.add(info)
  ok(path)

suite "Path selector boundary":
  var
    pool: MixNodePool
    nodes: seq[MixPubInfo]
    selector: SuppliedPathSelector
    request: PathRequest

  setup:
    pool = MixNodePool.new(PeerStore.new())
    nodes = MixNodeInfo.generateRandomMany(MaxPathLength + 1, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes[0 ..< MaxPathLength])
    selector = SuppliedPathSelector(nodePool: pool, path: nodes[0 ..< DefaultPathLength])
    request = PathRequest(purpose: PathPurpose.Forward, pathLength: DefaultPathLength)

  test "valid paths pass through for every supported length":
    for length in MinPathLength .. MaxPathLength:
      request.pathLength = length
      selector.path = nodes[0 ..< length]
      check selector.selectPath(request).get() == selector.path

  test "unusable pool entries are rejected without deleting them":
    request.constraints.fixedHops[2] = nodes[0]
    request.constraints.excludedNodeIds.incl(nodes[0].peerId)
    request.constraints.excludedNodeIds.incl(nodes[1].peerId)
    var invalid = nodes[2]
    invalid.mixPubKey = default(typeof(invalid.mixPubKey))
    pool.add(invalid)
    selector.path = @[nodes[3], nodes[4], nodes[0]]
    check selector.selectPath(request).isOk
    selector.path[0] = nodes[2]
    check selector.selectPath(request).isErr
    check pool.len == MaxPathLength

  test "fixed endpoints can be outside the pool and need no sampled candidates":
    selector.nodePool = MixNodePool.new(PeerStore.new())
    for position, node in selector.path:
      request.constraints.fixedHops[position] = node
      request.constraints.excludedNodeIds.incl(node.peerId)
    check selector.selectPath(request).get() == selector.path
    check selector.nodePool.len == 0

  test "invalid requests fail before invoking the strategy":
    request.pathLength = 0
    check selector.selectPath(request).error == "unsupported path length"
    check selector.calls == 0

  test "wrong lengths, repeated identities and nodes outside the pool are rejected":
    for path in [nodes[0 .. 1], @[nodes[0], nodes[0], nodes[1]],
                 @[nodes[0], nodes[1], nodes[^1]]]:
      selector.path = path
      check selector.selectPath(request).isErr
    selector.path = nodes[0 .. 2]
    request.constraints.excludedNodeIds.incl(nodes[0].peerId)
    check selector.selectPath(request).isErr

  test "fixed positions and their metadata must be preserved":
    request.constraints.fixedHops[2] = nodes[^1]
    check selector.selectPath(request).error == "selector changed a fixed hop"
    selector.path = @[nodes[0], nodes[1], nodes[^1]]
    check selector.selectPath(request).isOk
    selector.path[2].mixPubKey = nodes[2].mixPubKey
    check selector.selectPath(request).error == "selector changed a fixed hop"

  test "sampled metadata must match the current pool information":
    var updated = nodes[0]
    updated.mixPubKey = nodes[^1].mixPubKey
    pool.add(updated)
    check selector.selectPath(request).isErr
    selector.path[0] = updated
    check selector.selectPath(request).isOk

  test "strategies resolve updated metadata through the shared pool reference":
    let resolving = ResolvingPathSelector(
      nodePool: pool, peerIds: nodes[0 ..< DefaultPathLength].mapIt(it.peerId)
    )
    check resolving.selectPath(request).get()[0] == nodes[0]
    var updated = nodes[0]
    updated.mixPubKey = nodes[^1].mixPubKey
    pool.add(updated)
    check resolving.selectPath(request).get()[0] == updated

  test "pool additions and removals are visible without replacing stored identities":
    let ids = @[nodes[0].peerId, nodes[1].peerId, nodes[^1].peerId]
    let resolving = ResolvingPathSelector(nodePool: pool, peerIds: ids)
    check resolving.selectPath(request).error == "stored candidate is unavailable"
    pool.add(nodes[^1])
    check resolving.selectPath(request).get() == @[nodes[0], nodes[1], nodes[^1]]
    check pool.remove(nodes[0].peerId)
    check resolving.selectPath(request).error == "stored candidate is unavailable"
    check resolving.peerIds == ids

  test "missing selectors, missing pools and strategy errors are returned":
    let missing: PathSelector = nil
    check missing.selectPath(request).error == "missing selector or pool"
    check SuppliedPathSelector().selectPath(request).error == "missing selector or pool"
    check PathSelector(nodePool: pool).selectPath(request).error == "path selector is not implemented"
    selector.failure = "candidate set exhausted"
    check selector.selectPath(request).error == selector.failure
