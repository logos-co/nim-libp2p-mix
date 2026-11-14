# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sets, tables, sequtils]
import chronos, results
import libp2p/[multiaddress, peerstore, peerid]
import libp2p/crypto/secp
import libp2p_mix
import libp2p_mix/[serialization, tag_manager, surb_store, mix_protocol]
import libp2p_mix/session_path_selection
import ./utils
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

  test "base selector requires a concrete implementation":
    expect AssertionDefect:
      discard PathSelector(nodePool: pool).selectPath(request)

  test "missing selectors, missing pools and strategy errors are returned":
    let missing: PathSelector = nil
    check missing.selectPath(request).error == "missing selector or pool"
    check SuppliedPathSelector().selectPath(request).error == "missing selector or pool"
    selector.failure = "candidate set exhausted"
    check selector.selectPath(request).error == selector.failure

suite "Random selector constraint handling":
  test "fixed identities and exclusions are reserved before sampling":
    let pool = MixNodePool.new(PeerStore.new())
    let nodes = MixNodeInfo.generateRandomMany(6, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes[0 .. 3])
    var invalid = nodes[5]
    invalid.mixPubKey = default(typeof(invalid.mixPubKey))
    pool.add(invalid)
    var request = PathRequest(purpose: PathPurpose.Forward, pathLength: 4)
    request.constraints.fixedHops[1] = nodes[3]
    request.constraints.fixedHops[3] = nodes[4] # Explicit endpoint outside the pool.
    request.constraints.excludedNodeIds.incl(nodes[2].peerId)

    let path = RandomPathSelector.new(pool, rng()).selectPath(request).get()
    check path[1] == nodes[3]
    check path[3] == nodes[4]
    check [path[0].peerId, path[2].peerId].toHashSet ==
      [nodes[0].peerId, nodes[1].peerId].toHashSet
    check request.constraints.excludedNodeIds == [nodes[2].peerId].toHashSet
    check pool.peerIds().toHashSet ==
      [nodes[0].peerId, nodes[1].peerId, nodes[2].peerId,
       nodes[3].peerId, nodes[5].peerId].toHashSet

  test "candidate resolution observes pool changes and fails without enough usable nodes":
    let pool = MixNodePool.new(PeerStore.new())
    let nodes = MixNodeInfo.generateRandomMany(3, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes[0 .. 1])
    let selector = RandomPathSelector.new(pool, rng())
    var request = PathRequest(purpose: PathPurpose.Surb, pathLength: DefaultPathLength)
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

suite "Session candidate-set initialization":
  var
    pool: MixNodePool
    nodes: seq[MixPubInfo]

  setup:
    pool = MixNodePool.new(PeerStore.new())
    nodes = MixNodeInfo.generateRandomMany(8, rng()).mapIt(it.toMixPubInfo())
    pool.add(nodes)

  test "explicit state preserves sets independently of caller edits and pool changes":
    var supplied = @[@[nodes[3].peerId], nodes[0 .. 2].mapIt(it.peerId)]
    let originalText = $supplied
    # Construction requires identities only, even when a node is unavailable.
    require pool.remove(nodes[3].peerId)
    let state = SessionPathState.init(supplied).get()
    check $state.candidateSets() == originalText
    supplied[0][0] = nodes[7].peerId
    supplied[1][0].data[0] = supplied[1][0].data[0] xor 1.byte
    var inspected = state.candidateSets()
    inspected[0][0] = PeerId()
    inspected[1][0].data[0] = inspected[1][0].data[0] xor 1.byte
    inspected[1].setLen(0)
    var updated = nodes[3]
    updated.mixPubKey[0] = updated.mixPubKey[0] xor 1.byte
    pool.add(updated)
    check $state.candidateSets() == originalText

  test "state rejects empty sets, too many positions and repeated identities":
    let a = nodes[0].peerId
    for sets in [newSeq[seq[PeerId]](), @[newSeq[PeerId]()],
                 @[@[a, a]], @[@[a], @[a]]]:
      check SessionPathState.init(sets).isErr
    let tooMany = nodes[0 .. MaxPathLength].mapIt(@[it.peerId])
    check SessionPathState.init(tooMany).error == "unsupported session hop count"

  test "sampling resolved pool candidates creates disjoint sets without pool mutation":
    let excluded = [nodes[0].peerId].toHashSet
    var invalid = nodes[1]
    invalid.mixPubKey = default(typeof(invalid.mixPubKey))
    pool.add(invalid)
    let candidates = resolveCandidates(pool, pool.peerIds(), excluded)
    let state = sampleSessionState(candidates, rng(), 2, 3).get()
    let sets = state.candidateSets()
    require sets.len == 2
    var selected: HashSet[PeerId]
    for ids in sets:
      check ids.len == 3
      for peerId in ids:
        check peerId notin selected
        selected.incl(peerId)
    check selected == nodes[2 .. nodes.high].mapIt(it.peerId).toHashSet
    check pool.peerIds().toHashSet == nodes.mapIt(it.peerId).toHashSet

  test "sampling trusted candidates cannot expand beyond the supplied input":
    let trusted = nodes[0 .. 5].mapIt(it.peerId)
    let candidates = resolveCandidates(pool, trusted, default(HashSet[PeerId]))
    let state = sampleSessionState(candidates, rng(), 2, 3).get()
    check state.candidateSets().concat().toHashSet == trusted.toHashSet
    let restricted = resolveCandidates(pool, trusted, [trusted[0]].toHashSet)
    check sampleSessionState(restricted, rng(), 2, 3).error ==
      "not enough usable mix nodes for session candidate sets"
    # Duplicate input must not bias sampling, even if enough unique nodes exist.
    check sampleSessionState(candidates & @[candidates[0]], rng(), 2, 3).error ==
      "duplicate session candidate identity"
    check pool.len == nodes.len

  test "sampling rejects invalid counts, absent randomness and candidate shortage":
    for count in [0, -1, MaxPathLength + 1]:
      check sampleSessionState(nodes, rng(), count, 3).error ==
        "unsupported session hop count"
    for count in [0, -1]:
      check sampleSessionState(nodes, rng(), 2, count).error ==
        "session candidate count must be positive"
    for count in [5, high(int)]:
      check sampleSessionState(nodes, rng(), 2, count).error ==
        "not enough usable mix nodes for session candidate sets"
    check sampleSessionState(nodes, nil, 2, 3).error == "missing CSPRNG"
    check sampleSessionState([], rng(), 2, 3).isErr

# Save the requests received from Mix so tests can inspect their constraints.
# Return a deliberate error to stop execution before network transmission.
type RecordingSelector = ref object of PathSelector
  requests: seq[PathRequest]
  forwardPath: MixPath

method samplePath(
    selector: RecordingSelector, request: PathRequest
): Result[MixPath, string] {.gcsafe, raises: [].} =
  selector.requests.add(request)
  if request.purpose == PathPurpose.Forward and selector.forwardPath.len > 0:
    return ok(selector.forwardPath)
  err("test selector invoked")

suite "Mix path selection integration":
  var
    mix: MixProtocol
    nodes: seq[MixPubInfo]
    shared, session: RecordingSelector

  setup:
    let infos = MixNodeInfo.generateRandomMany(5, rng())
    nodes = infos.mapIt(it.toMixPubInfo())
    mix = MixProtocol.new(
      infos[0], createSwitch(infos[0].multiAddr, Opt.some(infos[0].libp2pPrivKey)),
      tagManager = TagManager.new(autoStart = false),
      surbStore = SurbStore.new(autoStart = false),
    )
    check mix.defaultPathSelector of RandomPathSelector
    check mix.defaultPathSelector.nodePool == mix.nodePool
    mix.nodePool.add(nodes[0 .. 3])
    shared = RecordingSelector(nodePool: mix.nodePool)
    session = RecordingSelector(nodePool: mix.nodePool)
    mix.defaultPathSelector = shared

  test "both send overloads pass session selectors and fix the destination last":
    let pooled = waitFor mix.send(
      MixDestination.exitNode(nodes[3].peerId), "/test/1.0.0", @[1.byte], session
    )
    let explicit = waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte], session)
    check pooled.error == "test selector invoked"
    check explicit.error == "test selector invoked"
    require session.requests.len == 2
    for i, destination in [nodes[3], nodes[4]]:
      let request = session.requests[i]
      check request.purpose == PathPurpose.Forward
      check request.pathLength == DefaultPathLength
      check request.constraints.fixedHops.getOrDefault(DefaultPathLength - 1) == destination
      check request.constraints.excludedNodeIds == [nodes[0].peerId, destination.peerId].toHashSet
    check shared.requests.len == 0
    check mix.defaultPathSelector == shared
    check mix.nodePool.get(nodes[4].peerId).isNone

  test "createSurb passes the session selector and fixes the current local endpoint":
    let newAddr = MultiAddress.init("/ip4/127.0.0.1/tcp/9999").get()
    require mix.setLocalMultiAddr(newAddr).isOk
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId), session).error ==
      "test selector invoked"
    require session.requests.len == 1
    let request = session.requests[0]
    var local = nodes[0]
    local.multiAddr = newAddr
    check request.purpose == PathPurpose.Surb
    check request.constraints.fixedHops.getOrDefault(DefaultPathLength - 1) == local
    check request.constraints.excludedNodeIds == [local.peerId, nodes[4].peerId].toHashSet
    check shared.requests.len == 0
    check mix.defaultPathSelector == shared

  test "send, createSurb and cover use the shared default when no selector is given":
    check (waitFor mix.send(nodes[4], "/test/1.0.0", @[1.byte])).isErr
    check mix.createSurb(MixDestination.exitNode(nodes[4].peerId)).isErr
    check (waitFor mix.buildCoverPacket(0)).error == "test selector invoked"
    check shared.requests.mapIt(it.purpose) ==
      @[PathPurpose.Forward, PathPurpose.Surb, PathPurpose.Cover]
    let cover = shared.requests[^1]
    check cover.constraints.fixedHops.getOrDefault(DefaultPathLength - 1) == nodes[0]
    check cover.constraints.excludedNodeIds == [nodes[0].peerId].toHashSet

  test "legacy sends reuse the selector for SURBs and exclude the selected forward exit":
    session.forwardPath = nodes[1 .. 3]
    let sent = waitFor mix.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](), @[1.byte], "/test/1.0.0",
      MixDestination.forwardToAddr(nodes[4].peerId, nodes[4].multiAddr), 1, session,
    )
    check sent.error == "Could not prepend SURBs: test selector invoked"
    require session.requests.len == 2
    let forward = session.requests[0]
    check forward.purpose == PathPurpose.Forward
    check forward.constraints.fixedHops.len == 0
    check forward.constraints.excludedNodeIds == [nodes[0].peerId, nodes[4].peerId].toHashSet
    let surb = session.requests[1]
    check surb.purpose == PathPurpose.Surb
    check surb.constraints.fixedHops.getOrDefault(DefaultPathLength - 1) == nodes[0]
    check surb.constraints.excludedNodeIds ==
      [nodes[0].peerId, nodes[3].peerId, nodes[4].peerId].toHashSet
    check shared.requests.len == 0
    check mix.surbCredsLen == 0
