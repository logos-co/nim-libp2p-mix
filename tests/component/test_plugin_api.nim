# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/[protocols/ping, peerid, switch, builders]
import libp2p_mix
import libp2p_mix/mix_protocol

import ../tools/[lifecycle, unittest, crypto]
import ../utils

suite "Mix Protocol - Plug-in API":
  asyncTeardown:
    checkTrackers()

  asyncTest "registered service handles delivery and unregister restores fallback":
    let nodes = await setupMixNodes(5)
    let sender = nodes[0]
    let destination = nodes[^1]
    let destinationId = destination.switch.peerInfo.peerId
    let fallbackProto = NoReplyProtocol.new()
    destination.switch.mount(fallbackProto)

    let deliveries = newAsyncQueue[MixDelivery]()
    let handler: MixDeliveryHandler = proc(
        delivery: MixDelivery
    ): Future[void] {.async: (raises: [CancelledError]).} =
      await deliveries.put(delivery)

    destination.registerMixDeliveryHandler(fallbackProto.codec, handler).expect(
      "could not register Mix delivery handler"
    )

    startAndDeferStop(nodes)

    let pluginPayload = @[1.byte, 2, 3]
    (await sender.send(
      MixDestination.exitNode(destinationId), fallbackProto.codec, pluginPayload
    )).expect("could not send plug-in payload")

    let delivery = await deliveries.get().wait(2.seconds)
    check:
      delivery.service == fallbackProto.codec
      delivery.payload == pluginPayload

    destination.unregisterMixDeliveryHandler(fallbackProto.codec)

    let legacyPayload = @[4.byte, 5, 6]
    let conn = sender
      .toConnection(MixDestination.exitNode(destinationId), fallbackProto.codec)
      .expect("could not build legacy connection")
    await conn.writeLp(legacyPayload)
    await conn.close()

    let received = await fallbackProto.receivedMessages.get().wait(2.seconds)
    check received.data == legacyPayload

  asyncTest "handled raw SURB reply is recovered by the plug-in":
    let nodes = await setupMixNodes(5)
    let sender = nodes[0]
    let destination = nodes[^1]
    let mixDestination = MixDestination.exitNode(destination.switch.peerInfo.peerId)
    let recoveredPayloads = newAsyncQueue[seq[byte]]()

    var created = sender.createSurb(mixDestination).expect("could not create SURB")
    let credential = created.credential

    let handler: RawSurbReplyHandler = proc(
        reply: RawSurbReply
    ): Future[RawSurbReplyDisposition] {.async: (raises: [CancelledError]).} =
      if reply.identifier != credential.identifier:
        return RawSurbReplyDisposition.Unhandled

      let payload = recoverReply(credential, reply).expect("could not recover reply")
      await recoveredPayloads.put(payload)
      return RawSurbReplyDisposition.Handled

    sender.registerRawSurbReplyHandler(handler).expect(
      "could not register raw SURB reply handler"
    )

    startAndDeferStop(nodes)

    let payload = @[7.byte, 8, 9]
    (await destination.sendWithSurb(move(created.surb), payload)).expect(
      "could not send SURB reply"
    )

    check (await recoveredPayloads.get().wait(2.seconds)) == payload

  asyncTest "unhandled raw SURB reply falls back to embedded connection":
    let nodes = await setupMixNodes(
      5, destReadBehavior = Opt.some((codec: PingCodec, callback: readExactly(32)))
    )
    let sender = nodes[0]
    let destination = nodes[^1]
    let pingProto = Ping.new(rng = rng())
    destination.switch.mount(pingProto)
    let unhandledReplies = newAsyncQueue[byte]()

    let handler: RawSurbReplyHandler = proc(
        reply: RawSurbReply
    ): Future[RawSurbReplyDisposition] {.async: (raises: [CancelledError]).} =
      await unhandledReplies.put(1)
      return RawSurbReplyDisposition.Unhandled

    sender.registerRawSurbReplyHandler(handler).expect(
      "could not register raw SURB reply handler"
    )

    startAndDeferStop(nodes)

    let conn = sender
      .toConnection(
        MixDestination.exitNode(destination.switch.peerInfo.peerId),
        pingProto.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
      )
      .expect("could not build legacy connection")

    let roundTripTime = await pingProto.ping(conn)
    await conn.close()

    discard await unhandledReplies.get().wait(2.seconds)
    check roundTripTime > 0.seconds
