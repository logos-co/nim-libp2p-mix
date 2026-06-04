# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Mix Protocol Ping Example
##
## This example demonstrates using the Mix protocol with the Ping protocol.
## It creates a set of mix nodes that form an anonymous overlay network,
## then sends a ping through the mix network to a destination node and
## receives the response via Single Use Reply Blocks (SURBs).

{.used.}

import chronicles, chronos, results
import std/[strformat, sequtils]
import
  libp2p/
    [protocols/ping, peerid, multiaddress, switch, builders, crypto/crypto, crypto/secp]
import libp2p_mix
import libp2p_mix/mix_protocol
import libp2p_mix/curve25519

const NumMixNodes = 10

proc createSwitch(
    multiAddr: MultiAddress,
    rng: Rng,
    libp2pPrivKey: Opt[SkPrivateKey] = Opt.none(SkPrivateKey),
): Switch =
  let skkey = libp2pPrivKey.valueOr(SkKeyPair.random(rng).seckey)
  let privKey = PrivateKey(scheme: Secp256k1, skkey: skkey)
  SwitchBuilder
    .new()
    .withRng(rng)
    .withPrivateKey(privKey)
    .withAddress(multiAddr)
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

proc mixPingSimulation() {.async: (raises: [CatchableError]).} =
  let rng = newRng()
  let mixNodeInfos = MixNodeInfo.generateRandomMany(NumMixNodes, rng)
  var switches: seq[Switch] = @[]
  var mixProtos: seq[MixProtocol] = @[]

  # Set up mix protocols on each mix node
  for nodeInfo in mixNodeInfos:
    var switch = createSwitch(nodeInfo.multiAddr, rng, Opt.some(nodeInfo.libp2pPrivKey))
    let proto = MixProtocol.new(nodeInfo, switch)

    # Populate nodePool with all other nodes' public info
    proto.nodePool.add(mixNodeInfos.includeAllExcept(nodeInfo))

    switch.mount(proto)

    switches.add(switch)
    mixProtos.add(proto)

  defer:
    await switches.mapIt(it.stop()).allFutures()

  # In this example, the destination is also the final mix node.
  let
    senderIndex = 0
    recipientIndex = NumMixNodes - 1

  let pingProto = Ping.new(rng = rng)
  switches[recipientIndex].mount(pingProto)

  # Start all switches
  await switches.mapIt(it.start()).allFutures()

  # Pick sender (first mix node) and send ping through the mix network
  let
    destination = switches[recipientIndex].peerInfo.peerId

  info "Sending ping through mix network",
    sender = switches[senderIndex].peerInfo.peerId, destination = destination

  # Create a connection through the mix network
  let conn = mixProtos[senderIndex]
    .toConnection(
      MixDestination.exitNode(destination),
      PingCodec,
      MixParameters(
        expectReply: Opt.some(true),
        numSurbs: Opt.some(byte(1)),
      ),
    )
    .expect("could not build connection")

  # Send ping and wait for response through the mix network
  let response = await pingProto.ping(conn)
  await conn.close()

  info "Ping response received through mix network", rtt = response

when isMainModule:
  waitFor(mixPingSimulation())
