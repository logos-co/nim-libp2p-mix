# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sets, tables, sequtils]
import chronos, results
import libp2p/[multiaddress, peerstore, peerid]
import libp2p/crypto/secp
import libp2p_mix
import libp2p_mix/[serialization, tag_manager, surb_store, mix_protocol, multiaddr]
import libp2p_mix/[cover_traffic, sphinx, key_rotation]
import ./utils
import ./tools/[unittest, crypto, lifecycle]

suite "Path request validation":
  var
    nodes: seq[MixPubInfo]
    request: PathRequest
    pathLength: int

  setup:
    nodes =
      MixNodeInfo.generateRandomMany(MaxPathLength, rng()).mapIt(it.toMixPubInfo())
    request = PathRequest(purpose: PathPurpose.Forward)
    pathLength = DefaultPathLength

  test "all purposes accept supported lengths with no fixed hops":
    for purpose in PathPurpose:
      for length in MinPathLength .. MaxPathLength:
        request.purpose = purpose
        pathLength = length
        check request.validatePathRequest(pathLength).isOk

  test "fixed hops may also be excluded from sampling":
    for purpose in PathPurpose:
      request.purpose = purpose
      request.constraints.fixedHops[pathLength - 1] = nodes[0]
      request.constraints.excludeNodes(DefaultPathLength, [nodes[0].peerId])
      check request.validatePathRequest(pathLength).isOk

  test "every position may be fixed when identities are distinct":
    pathLength = MaxPathLength
    for position, node in nodes:
      request.constraints.fixedHops[position] = node
    check request.validatePathRequest(pathLength).isOk

  test "unsupported selector lengths are rejected":
    for length in [-1, 0, 1, MinPathLength - 1, MaxPathLength + 1]:
      pathLength = length
      let outcome = request.validatePathRequest(pathLength)
      require outcome.isErr
      check outcome.error == "unsupported path length"

  test "fixed positions must be within the requested path":
    for position in [-1, pathLength]:
      request.constraints.fixedHops[position] = nodes[0]
      let outcome = request.validatePathRequest(pathLength)
      require outcome.isErr
      check outcome.error == "fixed hop index outside path"
      request.constraints.fixedHops.clear()

  test "positional exclusions reject invalid indices and conflicting fixed hops":
    for position in [-1, pathLength]:
      request.constraints.excludeNodesAt(position, [nodes[0].peerId])
      check request.validatePathRequest(pathLength).error ==
        "excluded hop index outside path"
      request.constraints.excludedNodeIds.clear()
    request.constraints.fixedHops[0] = nodes[0]
    request.constraints.excludeNodesAt(0, [nodes[0].peerId])
    check request.validatePathRequest(pathLength).error ==
      "fixed hop is excluded at its position"

  test "fixed hops cannot repeat an identity even with different metadata":
    var duplicate = nodes[0]
    duplicate.multiAddr = nodes[1].multiAddr
    request.constraints.fixedHops[0] = nodes[0]
    request.constraints.fixedHops[1] = duplicate
    let outcome = request.validatePathRequest(pathLength)
    require outcome.isErr
    check outcome.error == "duplicate fixed hop identity"

  test "fixed hops need a mix key and an encodable address":
    var invalid = nodes[0]
    invalid.mixPubKey = default(typeof(invalid.mixPubKey))
    request.constraints.fixedHops[0] = invalid
    let missingKey = request.validatePathRequest(pathLength)
    require missingKey.isErr
    check missingKey.error == "unusable fixed hop"

    invalid = nodes[0]
    invalid.multiAddr = MultiAddress.init("/ip6/::1/tcp/4242").get()
    request.constraints.fixedHops[0] = invalid
    let unsupportedAddress = request.validatePathRequest(pathLength)
    require unsupportedAddress.isErr
    check unsupportedAddress.error == "unusable fixed hop"

type SuppliedPathSelector = ref object of PathSelector
  path: MixPath
  calls: int
  failure: string
  length: int

method pathLength(selector: SuppliedPathSelector): int {.gcsafe, raises: [].} =
  if selector.length == 0: DefaultPathLength else: selector.length

method samplePath(
    selector: SuppliedPathSelector, request: PathRequest
): Result[MixPath, string] {.gcsafe, raises: [].} =
  inc selector.calls
  if selector.failure.len > 0:
    return err(selector.failure)
  ok(selector.path)

type ResolvingPathSelector = ref object of PathSelector
  peerIds: seq[PeerId]

method pathLength(selector: ResolvingPathSelector): int {.gcsafe, raises: [].} =
  DefaultPathLength

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
    nodes =
      MixNodeInfo.generateRandomMany(MaxPathLength + 1, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes[0 ..< MaxPathLength])
    selector =
      SuppliedPathSelector(nodePool: pool, path: nodes[0 ..< DefaultPathLength])
    request = PathRequest(purpose: PathPurpose.Forward)

  test "valid paths pass through for every supported length":
    for length in MinPathLength .. MaxPathLength:
      selector =
        SuppliedPathSelector(nodePool: pool, path: nodes[0 ..< length], length: length)
      check selector.selectPath(request).get() == selector.path

  test "the same request follows each selector's fixed length":
    let random = RandomPathSelector.new(pool, rng(), pathLength = 4)
    check random.pathLength == 4
    check random.selectPath(request).get().len == 4
    check not compiles(random.pathLength = 3)
    check RandomPathSelector.new(pool, rng()).selectPath(request).get().len == 3
    request.constraints.fixedHops[3] = nodes[3]
    check random.selectPath(request).get()[3] == nodes[3]
    check selector.selectPath(request).error == "fixed hop index outside path"
    check selector.calls == 0

  test "unusable pool entries are rejected without deleting them":
    request.constraints.fixedHops[2] = nodes[0]
    request.constraints.excludeNodes(DefaultPathLength, [nodes[0].peerId])
    request.constraints.excludeNodes(DefaultPathLength, [nodes[1].peerId])
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
    check selector.selectPath(request).get() == selector.path
    check selector.nodePool.len == 0

  test "invalid selector lengths and constraints fail before invoking the strategy":
    selector.length = -1
    check selector.selectPath(request).error == "unsupported path length"
    selector.length = DefaultPathLength
    request.constraints.fixedHops[selector.pathLength] = nodes[0]
    check selector.selectPath(request).error == "fixed hop index outside path"
    check selector.calls == 0

  test "wrong lengths, repeated identities and nodes outside the pool are rejected":
    for path in [
      nodes[0 .. 1], @[nodes[0], nodes[0], nodes[1]], @[nodes[0], nodes[1], nodes[^1]]
    ]:
      selector.path = path
      check selector.selectPath(request).isErr
    selector.path = nodes[0 .. 2]
    request.constraints.excludeNodes(DefaultPathLength, [nodes[0].peerId])
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

  test "base selector requires concrete length and sampling implementations":
    let base = PathSelector(nodePool: pool)
    expect AssertionDefect:
      discard base.pathLength
    expect AssertionDefect:
      discard base.samplePath(request)
    expect AssertionDefect:
      discard base.selectPath(request)

  test "missing selectors, missing pools and strategy errors are returned":
    let missing: PathSelector = nil
    check missing.selectPath(request).error == "missing selector or pool"
    check SuppliedPathSelector().selectPath(request).error == "missing selector or pool"
    selector.failure = "candidate set exhausted"
    check selector.selectPath(request).error == selector.failure

suite "Random selector constraint handling":
  test "random and session selectors apply first-position exclusions without losing candidates":
    let pool = MixNodePool.new(PeerStore.new())
    let nodes = MixNodeInfo.generateRandomMany(3, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes)
    let session =
      SessionPathSelector.new(pool, rng(), @[@[nodes[0].peerId, nodes[1].peerId]]).get()
    let random = RandomPathSelector.new(pool, rng())
    for selector in [PathSelector(random), PathSelector(session)]:
      var request = PathRequest(purpose: PathPurpose.Forward)
      request.constraints.fixedHops[2] = nodes[2]
      request.constraints.excludeNodesAt(0, [nodes[0].peerId])
      # The blocked first hop remains available at the second position.
      check selector.selectPath(request).get() == @[nodes[1], nodes[0], nodes[2]]
      request.constraints.excludeNodesAt(0, [nodes[1].peerId])
      check selector.selectPath(request).isErr
      request.constraints.excludedNodeIds[0].excl(nodes[0].peerId)
      check selector.selectPath(request).get() == @[nodes[0], nodes[1], nodes[2]]

    var request = PathRequest(purpose: PathPurpose.Forward)
    request.constraints.excludeNodesAt(0, [nodes[0].peerId])
    let custom = SuppliedPathSelector(nodePool: pool, path: nodes)
    check custom.selectPath(request).error == "selector returned an excluded node"

  test "fixed identities and exclusions are reserved before sampling":
    let pool = MixNodePool.new(PeerStore.new())
    let nodes = MixNodeInfo.generateRandomMany(6, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes[0 .. 3])
    var invalid = nodes[5]
    invalid.mixPubKey = default(typeof(invalid.mixPubKey))
    pool.add(invalid)
    var request = PathRequest(purpose: PathPurpose.Forward)
    request.constraints.fixedHops[1] = nodes[3]
    request.constraints.fixedHops[3] = nodes[4] # Explicit endpoint outside the pool.
    request.constraints.excludeNodes(4, [nodes[2].peerId])

    let path =
      RandomPathSelector.new(pool, rng(), pathLength = 4).selectPath(request).get()
    check path[1] == nodes[3]
    check path[3] == nodes[4]
    check [path[0].peerId, path[2].peerId].toHashSet ==
      [nodes[0].peerId, nodes[1].peerId].toHashSet
    check request.constraints.excludedNodeIds.getOrDefault(0) ==
      [nodes[2].peerId].toHashSet
    check pool.peerIds().toHashSet == [
      nodes[0].peerId,
      nodes[1].peerId,
      nodes[2].peerId,
      nodes[3].peerId,
      nodes[5].peerId,
    ].toHashSet

  test "candidate resolution observes pool changes and fails without enough usable nodes":
    let pool = MixNodePool.new(PeerStore.new())
    let nodes = MixNodeInfo.generateRandomMany(3, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes[0 .. 1])
    let selector = RandomPathSelector.new(pool, rng())
    var request = PathRequest(purpose: PathPurpose.Surb)
    request.constraints.fixedHops[2] = nodes[2]
    check selector.selectPath(request).isOk

    require pool.remove(nodes[0].peerId)
    check selector.selectPath(request).error == "not enough usable mix nodes"
    check pool.len == 1
    var updated = nodes[0]
    updated.mixPubKey = nodes[2].mixPubKey
    pool.add(updated)
    check updated in selector.selectPath(request).get()
    # With two fixed hops, sampling fills just one remaining position.
    request.constraints.fixedHops[0] = updated
    check selector.selectPath(request).get() == @[updated, nodes[1], nodes[2]]

suite "Session selector construction":
  var
    pool: MixNodePool
    nodes: seq[MixPubInfo]

  setup:
    pool = MixNodePool.new(PeerStore.new())
    nodes = MixNodeInfo.generateRandomMany(8, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes)

  test "explicit sets are copied and resolve current metadata at selection time":
    var supplied = @[@[nodes[3].peerId], nodes[0 .. 2].mapIt(it.peerId)]
    require pool.remove(nodes[3].peerId)
    let selector = SessionPathSelector.new(pool, rng(), supplied).get()
    supplied[0][0] = nodes[7].peerId
    supplied[1][0].data[0] = supplied[1][0].data[0] xor 1.byte
    supplied[1].setLen(0)
    var request = PathRequest(purpose: PathPurpose.Forward)
    request.constraints.fixedHops[2] = nodes[7]
    request.constraints.excludeNodes(
      DefaultPathLength, [nodes[1].peerId, nodes[2].peerId]
    )
    check selector.selectPath(request).error ==
      "no usable candidates in session set for this request"
    var updated = nodes[3]
    updated.mixPubKey[0] = updated.mixPubKey[0] xor 1.byte
    pool.add(updated)
    check selector.selectPath(request).get() == @[updated, nodes[0], nodes[7]]

  test "explicit construction rejects invalid sets and sets that cannot fit the length":
    let a = nodes[0].peerId
    for sets in [newSeq[seq[PeerId]](), @[newSeq[PeerId]()], @[@[a, a]], @[@[a], @[a]]]:
      check SessionPathSelector.new(pool, rng(), sets).isErr
    let tooMany = nodes[0 .. MaxPathLength].mapIt(@[it.peerId])
    check SessionPathSelector.new(pool, rng(), tooMany).error ==
      "unsupported session hop count"
    check SessionPathSelector.new(pool, rng(), tooMany[0 .. 3]).error ==
      "unsupported session hop count"

  test "pool initialization filters metadata and never expands its stored candidate set":
    for node in nodes[3 .. nodes.high]:
      var invalid = node
      invalid.mixPubKey = default(typeof(invalid.mixPubKey))
      pool.add(invalid)
    var params = SessionSelectorParams(pathLength: 3, hopCount: 1, candidatesPerHop: 3)
    let selector = SessionPathSelector.new(pool, rng(), params).get()
    # Caller changes after construction cannot alter the selector's configuration.
    params.pathLength = 4
    params.hopCount = 2
    check selector.pathLength == 3
    var request = PathRequest(purpose: PathPurpose.Forward)
    request.constraints.fixedHops[1] = nodes[6]
    request.constraints.fixedHops[2] = nodes[7]
    let originalIds = nodes[0 .. 2].mapIt(it.peerId).toHashSet
    for node in nodes[0 .. 2]:
      request.constraints.excludedNodeIds[0] = originalIds
      request.constraints.excludedNodeIds[0].excl(node.peerId)
      check selector.selectPath(request).get() == @[node, nodes[6], nodes[7]]
    check pool.len == nodes.len
    check SessionPathSelector.new(
      pool,
      rng(),
      SessionSelectorParams(pathLength: 3, hopCount: 2, candidatesPerHop: 2),
    ).error == "not enough usable mix nodes for session candidate sets"
    pool.add(nodes[3])
    request.constraints.excludedNodeIds[0] = originalIds
    check selector.selectPath(request).error ==
      "no usable candidates in session set for this request"

  test "parameter construction validates inputs and creates disjoint session positions":
    let valid = SessionSelectorParams(pathLength: 4, hopCount: 3, candidatesPerHop: 2)
    let selector = SessionPathSelector.new(pool, rng(), valid).get()
    check selector.pathLength == 4
    var request = PathRequest(purpose: PathPurpose.Forward)
    # No fixed endpoint here: all pool identities can be used during initialization.
    check selector.selectPath(request).get().len == 4
    request.purpose = PathPurpose.Surb
    check selector.selectPath(request).get().len == 4
    check SessionPathSelector.new(nil, rng(), valid).error == "missing mix node pool"
    check SessionPathSelector.new(pool, nil, valid).error == "missing CSPRNG"
    check SessionPathSelector.new(pool, rng(), SessionSelectorParams()).isErr
    for length in [low(int), MinPathLength - 1, MaxPathLength + 1, high(int)]:
      var params = valid
      params.pathLength = length
      check SessionPathSelector.new(pool, rng(), params).error ==
        "unsupported path length"
    for count in [-1, 0, valid.pathLength + 1]:
      var params = valid
      params.hopCount = count
      check SessionPathSelector.new(pool, rng(), params).error ==
        "unsupported session hop count"
    for size in [-1, 0, 3, high(int)]:
      var params = valid
      params.candidatesPerHop = size
      let expected =
        if size < 1:
          "session candidate count must be positive"
        else:
          "not enough usable mix nodes for session candidate sets"
      check SessionPathSelector.new(pool, rng(), params).error == expected

suite "Session profiles":
  test "presets construct selectors for forward and SURB paths with sufficient candidates":
    let nodes = MixNodeInfo.generateRandomMany(11, rng()).mapIt(it.toMixPubInfo())
    for (profile, length, hops, size) in [
      (SessionProfile.Lite, 3, 1, 5),
      (SessionProfile.Standard, 3, 2, 5),
      (SessionProfile.Strict, 4, 3, 3),
    ]:
      let params = profile.params()
      check (params.pathLength, params.hopCount, params.candidatesPerHop) ==
        (length, hops, size)
      let pool = MixNodePool.new(PeerStore.new())
      let required = hops * size
      pool.add(nodes[0 ..< required])
      let selector = SessionPathSelector.new(pool, rng(), params).get()
      check selector.pathLength == length
      for purpose in [PathPurpose.Forward, PathPurpose.Surb]:
        var request = PathRequest(purpose: purpose)
        request.constraints.fixedHops[length - 1] = nodes[^1]
        let path = selector.selectPath(request).get()
        check path.len == length
        check path[^1] == nodes[^1]
      require pool.remove(nodes[0].peerId)
      check SessionPathSelector.new(pool, rng(), params).error ==
        "not enough usable mix nodes for session candidate sets"

suite "Session path selection":
  var
    pool: MixNodePool
    nodes: seq[MixPubInfo]
    candidateSets: seq[seq[PeerId]]
    request: PathRequest

  setup:
    pool = MixNodePool.new(PeerStore.new())
    nodes =
      MixNodeInfo.generateRandomMany(MaxPathLength + 3, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes[0 ..< nodes.high])
    candidateSets = @[@[nodes[0].peerId], @[nodes[1].peerId]]
    request = PathRequest(purpose: PathPurpose.Forward)
    request.constraints.fixedHops[2] = nodes[^1]

  test "sets stay nearest the initiator in forward and SURB paths at supported lengths":
    for count in 1 .. 2:
      let sets = candidateSets[0 ..< count]
      for length in MinPathLength .. MaxPathLength:
        let selector =
          SessionPathSelector.new(pool, rng(), sets, pathLength = length).get()
        request.constraints.fixedHops.clear()
        request.constraints.fixedHops[length - 1] = nodes[^1]
        for purpose in [PathPurpose.Forward, PathPurpose.Surb]:
          request.purpose = purpose
          let path = selector.selectPath(request).get()
          check path[^1] == nodes[^1]
          for index in 0 ..< count:
            let position =
              if purpose == PathPurpose.Forward:
                index
              else:
                length - 2 - index
            check path[position] == nodes[index]

  test "fixed hops and exclusions apply before choosing from session sets":
    candidateSets =
      @[@[nodes[0].peerId, nodes[2].peerId], @[nodes[1].peerId, nodes[3].peerId]]
    let selector =
      SessionPathSelector.new(pool, rng(), candidateSets, pathLength = 4).get()
    request.constraints.fixedHops.clear()
    request.constraints.fixedHops[1] = nodes[0]
    request.constraints.fixedHops[3] = nodes[^1]
    request.constraints.excludeNodes(4, [nodes[0].peerId, nodes[1].peerId])
    check selector.selectPath(request).get() ==
      @[nodes[2], nodes[0], nodes[3], nodes[^1]]
    request.purpose = PathPurpose.Surb
    check selector.selectPath(request).get() ==
      @[nodes[3], nodes[0], nodes[2], nodes[^1]]

  test "unavailable session candidates fail only the request and recover without replacing sets":
    candidateSets = @[@[nodes[0].peerId, nodes[2].peerId], @[nodes[1].peerId]]
    let selector = SessionPathSelector.new(pool, rng(), candidateSets).get()
    var invalid = nodes[0]
    invalid.mixPubKey = default(typeof(invalid.mixPubKey))
    pool.add(invalid)
    var updated = nodes[2]
    updated.mixPubKey[0] = updated.mixPubKey[0] xor 1.byte
    pool.add(updated)
    check selector.selectPath(request).get()[0] == updated
    require pool.remove(nodes[2].peerId)
    check selector.selectPath(request).error ==
      "no usable candidates in session set for this request"
    pool.add(updated)
    check selector.selectPath(request).get() == @[updated, nodes[1], nodes[^1]]
    check pool.len == nodes.len - 1
    # Retry the same selector and candidate sets when request exclusions change.
    request.constraints.excludeNodes(
      DefaultPathLength, [nodes[0].peerId, nodes[2].peerId]
    )
    check selector.selectPath(request).error ==
      "no usable candidates in session set for this request"
    request.constraints.excludedNodeIds.clear()
    check selector.selectPath(request).get() == @[updated, nodes[1], nodes[^1]]

  test "invalid setup and incompatible requests fail without ending a valid session":
    check SessionPathSelector.new(nil, rng(), candidateSets).isErr
    check SessionPathSelector.new(pool, nil, candidateSets).isErr
    check SessionPathSelector.new(pool, rng(), newSeq[seq[PeerId]]()).isErr
    for length in [low(int), MinPathLength - 1, MaxPathLength + 1, high(int)]:
      check SessionPathSelector.new(pool, rng(), candidateSets, length).error ==
        "unsupported path length"
      expect AssertionDefect:
        discard RandomPathSelector.new(pool, rng(), length)
    let selector = SessionPathSelector.new(pool, rng(), candidateSets).get()
    check selector.pathLength == DefaultPathLength
    check not compiles(selector.pathLength = 4)
    request.constraints.fixedHops[0] = nodes[3]
    check selector.selectPath(request).error ==
      "not enough unfilled positions for session candidate sets"
    request.constraints.fixedHops.del(0)
    request.purpose = PathPurpose.Cover
    check selector.selectPath(request).error ==
      "session selector does not support cover paths"
    request.purpose = PathPurpose.Forward
    check selector.selectPath(request).isOk

  test "shortage for unrestricted random hops does not replace sets or end the session":
    pool = MixNodePool.new(PeerStore.new())
    pool.add(nodes[0 .. 1])
    let selector =
      SessionPathSelector.new(pool, rng(), candidateSets, pathLength = 4).get()
    request.constraints.fixedHops.clear()
    request.constraints.fixedHops[3] = nodes[^1]
    check selector.selectPath(request).error == "not enough usable mix nodes"
    check pool.len == 2
    pool.add(nodes[2])
    check selector.selectPath(request).get() ==
      @[nodes[0], nodes[1], nodes[2], nodes[^1]]

# Save the requests received from Mix so tests can inspect their constraints.
# Return a deliberate error to stop execution before network transmission.
type RecordingSelector = ref object of PathSelector
  requests: seq[PathRequest]
  forwardPath: MixPath
  length: int

method pathLength(selector: RecordingSelector): int {.gcsafe, raises: [].} =
  if selector.length == 0: DefaultPathLength else: selector.length

method samplePath(
    selector: RecordingSelector, request: PathRequest
): Result[MixPath, string] {.gcsafe, raises: [].} =
  selector.requests.add(request)
  if request.purpose == PathPurpose.Forward and selector.forwardPath.len > 0:
    return ok(selector.forwardPath)
  err("test selector invoked")

proc hasExclusions(request: PathRequest, length: int, ids: openArray[PeerId]): bool =
  for position in 0 ..< length:
    let expected =
      if request.constraints.fixedHops.hasKey(position):
        initHashSet[PeerId]()
      else:
        ids.toHashSet()
    if request.constraints.excludedNodeIds.getOrDefault(position) != expected:
      return false
  true

suite "Mix path selection integration":
  var
    mix: MixProtocol
    nodes: seq[MixPubInfo]
    shared, session: RecordingSelector

  setup:
    let infos = MixNodeInfo.generateRandomMany(5, rng())
    nodes = infos.mapIt(it.toMixPubInfo())
    mix = MixProtocol.new(
      infos[0],
      createSwitch(infos[0].multiAddr, Opt.some(infos[0].libp2pPrivKey)),
      tagManager = TagManager.new(autoStart = false),
      surbStore = SurbStore.new(autoStart = false),
    )
    check mix.coverPathSelector of RandomPathSelector
    check mix.coverPathSelector.nodePool == mix.nodePool
    check mix.defaultPathSelector of RandomPathSelector
    check mix.defaultPathSelector.nodePool == mix.nodePool
    check mix.defaultPathSelector != mix.coverPathSelector
    mix.nodePool.add(nodes[0 .. 3])
    shared = RecordingSelector(nodePool: mix.nodePool)
    session = RecordingSelector(nodePool: mix.nodePool)
    mix.coverPathSelector = shared
    waitFor mix.start()

  teardown:
    waitFor mix.stop()

  test "both send overloads fix the destination at the selector's last hop":
    for length in MinPathLength .. MaxPathLength:
      session = RecordingSelector(nodePool: mix.nodePool, length: length)
      let pooled = waitFor mix.send(
        MixDestination.exitNode(nodes[3].peerId),
        "/test/1.0.0",
        @[1.byte],
        selector = session,
      )
      let explicit =
        waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte], selector = session)
      check pooled.error == "test selector invoked"
      check explicit.error == "test selector invoked"
      require session.requests.len == 2
      for i, destination in [nodes[3], nodes[4]]:
        let request = session.requests[i]
        check request.purpose == PathPurpose.Forward
        check request.constraints.fixedHops.getOrDefault(length - 1) == destination
        check request.hasExclusions(length, [nodes[0].peerId, destination.peerId])
    check shared.requests.len == 0
    check mix.coverPathSelector == shared
    check mix.nodePool.get(nodes[4].peerId).isNone

  test "createSurb fixes the local endpoint at the selector's last hop":
    let newAddr = MultiAddress.init("/ip4/127.0.0.1/tcp/9999").get()
    require mix.setLocalMultiAddr(newAddr).isOk
    var local = nodes[0]
    local.multiAddr = newAddr
    for length in MinPathLength .. MaxPathLength:
      session = RecordingSelector(nodePool: mix.nodePool, length: length)
      check mix.createSurb(MixDestination.exitNode(nodes[4].peerId), selector = session).error ==
        "test selector invoked"
      require session.requests.len == 1
      let request = session.requests[0]
      check request.purpose == PathPurpose.Surb
      check request.constraints.fixedHops.getOrDefault(length - 1) == local
      check request.hasExclusions(length, [local.peerId, nodes[4].peerId])
    check shared.requests.len == 0
    check mix.coverPathSelector == shared

  test "normal default random selection and cover selection remain separate":
    for node in nodes[1 .. 3]:
      require mix.nodePool.remove(node.peerId)
    # No usable relays: the normal default fails without consulting the cover selector.
    check (waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte])).error ==
      "not enough usable mix nodes"
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId)).error ==
      "not enough usable mix nodes"
    mix.nodePool.add(nodes[1 .. 2])
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId)).isOk
    # Two relays suffice for the default length, but not a four-hop random path.
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId), pathLength = 4).error ==
      "not enough usable mix nodes"
    check (waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte], pathLength = 4)).error ==
      "not enough usable mix nodes"
    check (
      waitFor mix.send(
        MixDestination.exitNode(nodes[2].peerId),
        "/test/1.0.0",
        @[1.byte],
        pathLength = 4,
      )
    ).error == "not enough usable mix nodes"
    mix.nodePool.add(nodes[3])
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId), pathLength = 4).isOk
    check shared.requests.len == 0
    check (waitFor mix.buildCoverPacket(0)).error == "test selector invoked"
    require shared.requests.len == 1
    let cover = shared.requests[0]
    check cover.purpose == PathPurpose.Cover
    check cover.constraints.fixedHops.getOrDefault(DefaultPathLength - 1) == nodes[0]
    check cover.hasExclusions(DefaultPathLength, [nodes[0].peerId])
    # A custom selector must match the cover configuration (three by default).
    shared = RecordingSelector(nodePool: mix.nodePool, length: 4)
    mix.coverPathSelector = shared
    check (waitFor mix.buildCoverPacket(0)).error ==
      "cover selector path length does not match cover configuration"
    check shared.requests.len == 0

  test "omitted selectors reuse the normal default while explicit choices override it":
    let normal = RecordingSelector(nodePool: mix.nodePool, length: 4)
    mix.defaultPathSelector = normal
    check (waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte])).error ==
      "test selector invoked"
    check (
      waitFor mix.send(
        MixDestination.exitNode(nodes[3].peerId), "/test/1.0.0", @[1.byte]
      )
    ).error == "test selector invoked"
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId)).error ==
      "test selector invoked"
    check (
      waitFor mix.anonymizeLocalProtocolSend(
        newAsyncQueue[seq[byte]](),
        @[1.byte],
        "/test/1.0.0",
        MixDestination.exitNode(nodes[3].peerId),
        0,
      )
    ).error == "test selector invoked"
    require normal.requests.len == 4
    for request in normal.requests:
      check request.constraints.fixedHops.hasKey(3)
    check shared.requests.len == 0
    check (waitFor mix.buildCoverPacket(0)).error == "test selector invoked"
    require shared.requests.len == 1
    check shared.requests[0].constraints.fixedHops.hasKey(2)

    check (waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte], selector = session)).error ==
      "test selector invoked"
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId), selector = session).error ==
      "test selector invoked"
    check session.requests.len == 2
    for node in nodes[1 .. 3]:
      require mix.nodePool.remove(node.peerId)
    check (waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte], pathLength = 3)).error ==
      "not enough usable mix nodes"
    check (
      waitFor mix.send(
        MixDestination.exitNode(nodes[0].peerId),
        "/test/1.0.0",
        @[1.byte],
        pathLength = 3,
      )
    ).error == "not enough usable mix nodes"
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId), pathLength = 3).error ==
      "not enough usable mix nodes"
    check normal.requests.len == 4
    check mix.defaultPathSelector == normal
    check mix.coverPathSelector == shared
    mix.defaultPathSelector = nil
    check (waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte])).error ==
      "missing selector or pool"
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId)).error ==
      "missing selector or pool"

  test "selector and explicit length cannot be supplied together":
    check not compiles(
      mix.send(nodes[4], "/test/1.0.0", @[1.byte], session, pathLength = 4)
    )
    check not compiles(
      mix.send(
        MixDestination.exitNode(nodes[3].peerId),
        "/test/1.0.0",
        @[1.byte],
        session,
        pathLength = 4,
      )
    )
    check not compiles(
      mix.createSurb(MixDestination.exitNode(nodes[4].peerId), session, pathLength = 4)
    )
    check not compiles(
      mix.anonymizeLocalProtocolSend(
        newAsyncQueue[seq[byte]](),
        @[1.byte],
        "/test/1.0.0",
        MixDestination.exitNode(nodes[3].peerId),
        1,
        session,
        pathLength = 4,
      )
    )

  test "createSurb builds three- and four-hop reply blocks using session sets":
    for length in [DefaultPathLength, 4]:
      let sets = nodes[1 ..< length].mapIt(@[it.peerId])
      let selector =
        SessionPathSelector.new(mix.nodePool, rng(), sets, pathLength = length).get()
      let reply = mix
        .createSurb(MixDestination.exitNode(nodes[4].peerId), selector)
        .expectMove("create SURB")
      let firstHop = bytesToMultiAddr(reply.surb.hop.get()).get()
      check firstHop[0] == nodes[length - 1].peerId
    check shared.requests.len == 0
    check mix.coverPathSelector == shared

  test "unsupported lengths fail before sampling or registering reply credentials":
    for length in [low(int), -1, 0, MinPathLength - 1, MaxPathLength + 1, high(int)]:
      check (
        waitFor mix.send(
          MixDestination.exitNode(nodes[3].peerId),
          "/test/1.0.0",
          @[1.byte],
          pathLength = length,
        )
      ).error == "unsupported path length"
      check (waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte], pathLength = length)).error ==
        "unsupported path length"
      check mix.createSurb(
        MixDestination.exitNode(nodes[4].peerId), pathLength = length
      ).error == "unsupported path length"
      check (
        waitFor mix.anonymizeLocalProtocolSend(
          newAsyncQueue[seq[byte]](),
          @[1.byte],
          "/test/1.0.0",
          MixDestination.exitNode(nodes[3].peerId),
          1,
          pathLength = length,
        )
      ).error == "unsupported path length"
    check session.requests.len == 0
    check shared.requests.len == 0
    check mix.surbCredsLen == 0

  test "legacy sends pass the same length and selector to embedded SURBs":
    let extra = MixNodeInfo.generateRandomMany(1, rng())[0].toMixPubInfo()
    mix.nodePool.add(extra)
    for length in [DefaultPathLength, 4]:
      session = RecordingSelector(nodePool: mix.nodePool, length: length)
      session.forwardPath = nodes[1 .. 3]
      if length == 4:
        session.forwardPath.add(extra)
      let sent = waitFor mix.anonymizeLocalProtocolSend(
        newAsyncQueue[seq[byte]](),
        @[1.byte],
        "/test/1.0.0",
        MixDestination.forwardToAddr(nodes[4].peerId, nodes[4].multiAddr),
        1,
        session,
      )
      check sent.error == "Could not prepend SURBs: test selector invoked"
      require session.requests.len == 2
      let forward = session.requests[0]
      check forward.purpose == PathPurpose.Forward
      check forward.constraints.fixedHops.len == 0
      check forward.hasExclusions(length, [nodes[0].peerId, nodes[4].peerId])
      let surb = session.requests[1]
      check surb.purpose == PathPurpose.Surb
      check surb.constraints.fixedHops.getOrDefault(length - 1) == nodes[0]
      check surb.hasExclusions(
        length, [nodes[0].peerId, session.forwardPath[^1].peerId, nodes[4].peerId]
      )
      check mix.surbCredsLen == 0
    check shared.requests.len == 0

suite "Session paths with key rotation":
  test "selected SURB paths preserve rotation deadlines and use current keys":
    for length in [MinPathLength, MaxPathLength]:
      let originals = MixNodeInfo.generateRandomMany(length, rng())
      let config = KeyRotationConfig.init().get()
      var rings: seq[MixKeyRing]
      var infos: seq[MixPubInfo]
      for node in originals:
        let ring = MixKeyRing.new(config, rng(), replayTableCapacity = 32)
        ring.update()
        rings.add(ring)
        var info = node.toMixPubInfo()
        info.mixPubKey = ring.currentPublicKey().get()
        infos.add(info)
      defer:
        for ring in rings:
          waitFor ring.stop()
      let mix = MixProtocol.new(
        originals[0],
        createSwitch(originals[0].multiAddr, Opt.some(originals[0].libp2pPrivKey)),
        tagManager = TagManager.new(autoStart = false),
        surbStore = SurbStore.new(autoStart = false),
        keyRing = Opt.some(rings[0]),
      )
      mix.nodePool.add(infos[1 ..^ 1])
      let sets = infos[1 ..^ 1].mapIt(@[it.peerId])
      let selector = SessionPathSelector.new(mix.nodePool, rng(), sets, length).get()
      let destination = MixDestination.exitNode(PeerId.random(rng()).get())
      let built =
        mix.createSurb(destination, selector).expectMove("create rotating SURB")
      let staleAt = mix.nodePool.staleAt(infos[1 ..^ 1].mapIt(it.peerId)).get()
      check built.dispatchBefore.get() == staleAt
      check built.credentialsExpireAt.get() == staleAt + config.surbLifetime
      check built.replyHoldTime.get() == config.surbHoldTime
      check built.replyTransitAllowance.get() ==
        config.surbLifetime - config.surbHoldTime
      let message = newSeq[byte](MessageSize)
      var packet = useSURB(built.surb, message)
      # SURBs traverse initiator-relative session sets in reverse, then return home.
      for position in 0 ..< length:
        let index = length - 1 - position
        var matched = matchKey(packet, rings[index].candidates()).get()
        let processed = processSphinxPacket(packet, matched).get()
        if index == 0:
          require processed.status == Reply
          let reply = RawSurbReply(
            identifier: processed.id, encryptedPayload: processed.delta_prime
          )
          check recoverSphinxReply(built.credential, reply).get() == message
        else:
          require processed.status == Intermediate
          packet = SphinxPacket.deserialize(processed.serializedSphinxPacket).get()

suite "Configured cover paths":
  test "cover configuration builds loops of the configured length and rejects mismatched selectors":
    for length in MinPathLength .. MaxPathLength:
      let infos = MixNodeInfo.generateRandomMany(length, rng())
      let ct = ConstantRateCoverTraffic.new(pathLength = length)
      let mix = MixProtocol.new(
        infos[0],
        createSwitch(infos[0].multiAddr, Opt.some(infos[0].libp2pPrivKey)),
        tagManager = TagManager.new(autoStart = false),
        surbStore = SurbStore.new(autoStart = false),
        coverTraffic = Opt.some(CoverTraffic(ct)),
      )
      mix.nodePool.add(infos[1 ..^ 1].mapIt(it.toMixPubInfo()))
      check mix.coverPathSelector of RandomPathSelector
      check mix.coverPathSelector.pathLength == length
      check mix.defaultPathSelector.pathLength == DefaultPathLength
      check mix.defaultPathSelector != mix.coverPathSelector
      let built = (waitFor mix.buildCoverPacket(0)).get()
      check built.packet.len == PacketSize
      var packet = SphinxPacket.deserialize(built.packet).get()
      var peer = built.firstHopPeerId
      var seen: HashSet[PeerId]
      var tags = TagManager.new(autoStart = false)
      for position in 0 ..< length:
        require peer notin seen
        seen.incl(peer)
        let matches = infos.filterIt(it.peerId == peer)
        require matches.len == 1
        let processed = processSphinxPacket(packet, matches[0].mixPrivKey, tags).get()
        if position == length - 1:
          check peer == infos[0].peerId
          check processed.status == Exit
        else:
          require processed.status == Intermediate
          peer = bytesToMultiAddr(processed.nextHop.get()).get()[0]
          packet = SphinxPacket.deserialize(processed.serializedSphinxPacket).get()

      # Do not silently change scheduling if the shared selector is replaced.
      let mismatch = RecordingSelector(
        nodePool: mix.nodePool,
        length: (if length == DefaultPathLength: 4 else: DefaultPathLength),
      )
      mix.coverPathSelector = mismatch
      check (waitFor mix.buildCoverPacket(0)).error ==
        "cover selector path length does not match cover configuration"
      check mismatch.requests.len == 0

suite "Session selector round trips":
  asyncTeardown:
    checkTrackers()

  asyncTest "independent sessions reuse selectors for sends and SURBs and recover after pool changes":
    let nodes = await setupMixNodes(6)
    let sender = nodes[0]
    let destination = nodes[^1]
    let destinationInfo = destination.localMixPubInfo().get()
    let target = MixDestination.exitNode(destinationInfo.peerId)
    let relays = nodes[1 .. 4].mapIt(it.localMixPubInfo().get())
    # Singleton sets make the two sessions' routes deterministic without
    # exposing private state. The longer session does not depend on relays[0].
    let first = SessionPathSelector
      .new(sender.nodePool, rng(), @[@[relays[0].peerId], @[relays[1].peerId]])
      .get()
    let second = SessionPathSelector
      .new(
        sender.nodePool,
        rng(),
        @[@[relays[2].peerId], @[relays[1].peerId], @[relays[3].peerId]],
        pathLength = 4,
      )
      .get()
    let coverSelector = sender.coverPathSelector
    let deliveries = newAsyncQueue[MixDelivery]()
    let replies = newAsyncQueue[RawSurbReply]()
    const service = "/session-path-test/1.0.0"
    let deliveryHandler: MixDeliveryHandler = proc(
        delivery: MixDelivery
    ): Future[void] {.async: (raises: [CancelledError]).} =
      await deliveries.put(delivery)
    let replyHandler: RawSurbReplyHandler = proc(
        reply: RawSurbReply
    ): Future[RawSurbReplyDisposition] {.async: (raises: [CancelledError]).} =
      await replies.put(reply)
      return RawSurbReplyDisposition.Handled
    destination.registerMixDeliveryHandler(service, deliveryHandler).expect(
      "register delivery"
    )
    sender.registerRawSurbReplyHandler(replyHandler).expect("register replies")
    startAndDeferStop(nodes)

    proc roundTrip(selector: SessionPathSelector, payload: seq[byte]) {.async.} =
      var created =
        sender.createSurb(target, selector = selector).expectMove("create SURB")
      (await sender.send(destinationInfo, service, payload, selector = selector)).expect(
        "send"
      )
      check (await deliveries.get().wait(2.seconds)).payload == payload
      # In a real application its message envelope carries the SURB to the
      # destination. This local fixture hands it directly to the responder.
      (await destination.sendWithSurb(move(created.surb), payload)).expect("reply")
      let reply = await replies.get().wait(2.seconds)
      check recoverReply(created.credential, reply).get() == payload

    await roundTrip(first, @[1.byte])
    await roundTrip(second, @[2.byte])
    require sender.nodePool.remove(relays[0].peerId)
    check (await sender.send(destinationInfo, service, @[3.byte], selector = first)).error ==
      "no usable candidates in session set for this request"
    check sender.createSurb(target, selector = first).error ==
      "no usable candidates in session set for this request"
    await roundTrip(second, @[4.byte])
    sender.nodePool.add(relays[0])
    await roundTrip(first, @[5.byte])
    check sender.coverPathSelector == coverSelector
