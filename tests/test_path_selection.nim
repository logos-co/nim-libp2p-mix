# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sets, tables, sequtils]
import results
import libp2p/multiaddress
import libp2p_mix/[path_selection, mix_node, serialization]
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
