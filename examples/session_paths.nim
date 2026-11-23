# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Run two round trips per session profile over a local 12-node Mix network.
## Each session reuses one selector for sends and fresh SURBs. The example
## envelope is one serialized SURB followed by the payload to echo back.

import std/sequtils
import chronicles, chronos, results
import libp2p/[multiaddress, switch, builders, crypto/crypto, crypto/secp]
import libp2p_mix
import libp2p_mix/mix_protocol
from libp2p_mix/serialization import SurbSize

const
  NumMixNodes = 12
  Service = "/session-paths/echo/1.0.0"

proc createSwitch(node: MixNodeInfo, rng: Rng): Switch =
  SwitchBuilder
    .new()
    .withRng(rng)
    .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: node.libp2pPrivKey))
    .withAddress(node.multiAddr)
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

proc sessionPathsSimulation() {.async: (raises: [Exception]).} =
  let rng = newRng()
  let infos = MixNodeInfo.generateRandomMany(NumMixNodes, rng)
  var nodes: seq[MixProtocol]
  defer:
    await nodes.mapIt(it.stop()).allFutures()
    await nodes.mapIt(it.switch.stop()).allFutures()

  for nodeInfo in infos:
    let switch = createSwitch(nodeInfo, rng)
    let mix = MixProtocol.new(nodeInfo, switch)
    mix.nodePool.add(infos.includeAllExcept(nodeInfo))
    switch.mount(mix)
    nodes.add(mix)

  let sender = nodes[0]
  let responder = nodes[^1]
  let destination = MixDestination.exitNode(responder.localMixPubInfo().peerId)
  let deliveries = newAsyncQueue[MixDelivery]()
  let replies = newAsyncQueue[RawSurbReply]()
  # This example has one outstanding request at a time. An application with
  # concurrent requests would keep a table of identifiers and credentials.
  var expectedReply = Opt.none(SURBIdentifier)

  let deliveryHandler: MixDeliveryHandler = proc(
      delivery: MixDelivery
  ): Future[void] {.async: (raises: [CancelledError]).} =
    await deliveries.put(delivery)
  let replyHandler: RawSurbReplyHandler = proc(
      reply: RawSurbReply
  ): Future[RawSurbReplyDisposition] {.async: (raises: [CancelledError]).} =
    if expectedReply.isNone or reply.identifier != expectedReply.get():
      return RawSurbReplyDisposition.Unhandled
    await replies.put(reply)
    return RawSurbReplyDisposition.Handled

  responder.registerMixDeliveryHandler(Service, deliveryHandler).expect("register service")
  sender.registerRawSurbReplyHandler(replyHandler).expect("register reply handler")
  await nodes.mapIt(it.switch.start()).allFutures()
  await nodes.mapIt(it.start()).allFutures()

  for profile in SessionProfile:
    # Initialize once per logical session, before creating any reply blocks.
    # Standard needs ten distinct usable pool nodes; this pool contains eleven.
    # Request constraints exclude the destination from sampled relay positions.
    let selector = SessionPathSelector.new(
      sender.nodePool, rng, profile.params()
    ).expect("initialize session selector")

    for message in 1 .. 2:
      let payload = @[byte(ord(profile)), byte(message)]
      let created = sender.createSurb(destination, selector = selector).expect("create SURB")
      expectedReply = Opt.some(created.credential.identifier)
      # Only the SURB crosses the network; the credential stays with the sender.
      let envelope = serializeSurb(created.surb) & payload
      (await sender.send(destination, Service, envelope, selector = selector)).expect("send")

      # The responder receives the SURB through the forward packet, rather than
      # sharing the sender's local SURB object or selection state.
      let delivery = await deliveries.get().wait(10.seconds)
      doAssert delivery.payload.len >= SurbSize, "truncated request envelope"
      var surb = deserializeSurb(delivery.payload.toOpenArray(0, SurbSize - 1)).expect("decode SURB")
      let receivedPayload = delivery.payload[SurbSize ..^ 1]
      doAssert receivedPayload == payload, "forward payload mismatch"
      # No selector is needed here: the SURB already contains the return route.
      # It is consumed by this call, including if sending fails.
      (await responder.sendWithSurb(move(surb), receivedPayload)).expect("send reply")

      let reply = await replies.get().wait(10.seconds)
      let recovered = recoverReply(created.credential, reply).expect("recover reply")
      expectedReply = Opt.none(SURBIdentifier)
      doAssert recovered == payload, "reply payload mismatch"
      info "Session round trip completed",
        profile = $profile, pathLength = selector.pathLength, message = message

when isMainModule:
  waitFor(sessionPathsSimulation())
