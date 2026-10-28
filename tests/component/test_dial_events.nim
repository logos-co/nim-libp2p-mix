# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/sequtils
import chronos, results
import libp2p/[switch, multiaddress, peerid]
import libp2p_mix
import libp2p_mix/[mix_protocol, mix_events, delay_strategy]
import ../tools/[lifecycle, unittest, crypto, host_pool]
import ../utils

proc refusedPeer(): MixPubInfo =
  ## A peer at a local port where nothing listens. A dial to it fails at once.
  var info = MixNodeInfo.generateRandom(0, rng()).toMixPubInfo()
  info.multiAddr = MultiAddress.init("/ip4/127.0.0.1/tcp/1").get()
  info

proc mixNode(brokerCtx: BrokerContext): MixProtocol =
  let info = MixNodeInfo.generateRandom(0, rng())
  let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
  let mix = MixProtocol.new(
    info,
    sw,
    pool = HostPool.new(),
    brokerCtx = brokerCtx,
    delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
  )
  sw.mount(mix)
  mix

proc completeOnDialFailure(brokerCtx: BrokerContext, failed: Future[PeerId]) =
  ## Complete `failed` with the peer of the next MixHopDialFailed on `brokerCtx`.
  proc onDialFailure(
      event: MixHopDialFailed
  ): Future[void] {.async: (raises: []), gcsafe.} =
    if not failed.finished:
      failed.complete(event.peerId)

  discard MixHopDialFailed.listen(brokerCtx, onDialFailure)

proc nextDialFailure(brokerCtx: BrokerContext): Future[PeerId] =
  ## The peer of the next MixHopDialFailed event on `brokerCtx`.
  let failed = newFuture[PeerId]("test.nextDialFailure")
  brokerCtx.completeOnDialFailure(failed)
  failed

suite "Mix dial failure events":
  asyncTeardown:
    checkTrackers()

  asyncTest "a listener can detach during its own event callback":
    let ctx = NewBrokerContext()
    defer:
      await MixHopDialFailed.dropAllListeners(ctx)
    let called = newFuture[void]("detached listener called")
    var handle: MixHopDialFailedListener
    proc detachSelf(event: MixHopDialFailed) {.async: (raises: []), gcsafe.} =
      detachMixHopDialFailedListener(ctx, handle)
      called.complete()

    handle = MixHopDialFailed.listen(ctx, detachSelf).get()
    MixHopDialFailed.emit(ctx, MixHopDialFailed(peerId: refusedPeer().peerId))
    check await called.withTimeout(2.seconds)
    let cleanupTurn = newFuture[void]("detached bucket cleanup turn")
    callSoon(
      proc(_: pointer) {.gcsafe, raises: [].} =
        cleanupTurn.complete()
    )
    check await cleanupTurn.withTimeout(2.seconds)
    let again = newFuture[void]("replacement listener called")
    proc onAgain(event: MixHopDialFailed) {.async: (raises: []), gcsafe.} =
      again.complete()

    discard MixHopDialFailed.listen(ctx, onAgain).get()
    MixHopDialFailed.emit(ctx, MixHopDialFailed(peerId: refusedPeer().peerId))
    check await again.withTimeout(2.seconds)

  asyncTest "detaching one listener leaves another listener's active callback running":
    let ctx = NewBrokerContext()
    defer:
      await MixHopDialFailed.dropAllListeners(ctx)
    let started = newFuture[void]("second listener started")
    let release = newFuture[void]("release second listener")
    let outcome = newFuture[bool]("second listener outcome")
    var idleSeen, waitingSeen = 0
    proc idle(event: MixHopDialFailed) {.async: (raises: []), gcsafe.} =
      inc idleSeen

    proc waiting(event: MixHopDialFailed) {.async: (raises: []), gcsafe.} =
      inc waitingSeen
      if started.finished:
        return
      started.complete()
      try:
        await release
        outcome.complete(true)
      except CancelledError:
        outcome.complete(false)
      except CatchableError:
        outcome.complete(false)

    let first = MixHopDialFailed.listen(ctx, idle).get()
    discard MixHopDialFailed.listen(ctx, waiting).get()
    MixHopDialFailed.emit(ctx, MixHopDialFailed(peerId: refusedPeer().peerId))
    check await started.withTimeout(2.seconds)
    # The first listener goes while the second one's callback still waits.
    detachMixHopDialFailedListener(ctx, first)
    release.complete()
    check await outcome.withTimeout(2.seconds)
    check outcome.read()
    MixHopDialFailed.emit(ctx, MixHopDialFailed(peerId: refusedPeer().peerId))
    checkUntilTimeout:
      waitingSeen == 2
    check idleSeen == 1

  asyncTest "a sender emits the peer of a refused first hop on its own context":
    let ctx = NewBrokerContext()
    let otherCtx = NewBrokerContext()
    defer:
      await MixHopDialFailed.dropAllListeners(ctx)
      await MixHopDialFailed.dropAllListeners(otherCtx)
    let sender = mixNode(ctx)
    let peers = @[refusedPeer(), refusedPeer(), refusedPeer()]
    for peer in peers:
      sender.hostPool.addPeer(peer)
    let nodes = @[sender]
    startAndDeferStop(nodes)
    let elsewhere = nextDialFailure(otherCtx)

    # A request.
    var failed = nextDialFailure(ctx)
    let destination = MixNodeInfo.generateRandom(0, rng())
    let conn = sender
      .toConnection(
        MixDestination.init(destination.peerId, destination.multiAddr), "/test/dial/1"
      )
      .get()
    defer:
      await conn.close()
    expect LPStreamError:
      await conn.writeLp(@[1'u8]).wait(2.seconds)
    check (await failed.wait(2.seconds)) in peers.mapIt(it.peerId)

    # A cover packet.
    await MixHopDialFailed.dropAllListeners(ctx)
    failed = nextDialFailure(ctx)
    let cover = (await sender.buildCoverPacket()).get()
    check (
      await sender.sendCoverPacket(
        cover.firstHopPeerId, cover.firstHopAddr, cover.packet
      )
    ).isErr
    check (await failed.wait(2.seconds)) == cover.firstHopPeerId

    # Another context hears nothing.
    check not await elsewhere.withTimeout(200.milliseconds)

  asyncTest "a relay emits the peer of a refused next hop on its own context":
    let contexts = @[NewBrokerContext(), NewBrokerContext(), NewBrokerContext()]
    defer:
      for ctx in contexts:
        await MixHopDialFailed.dropAllListeners(ctx)
    let nodes = contexts.mapIt(mixNode(it))
    startAndDeferStop(nodes)
    for node in nodes:
      node.setLocalMultiAddr(node.switch.peerInfo.addrs[0]).expect("bound address")
    let (sender, relays) = (nodes[0], nodes[1 .. 2])
    let exit = refusedPeer()
    for relay in relays:
      sender.hostPool.addPeer(relay.localMixPubInfo())
    sender.hostPool.addPeer(exit)
    # The path is the two relays in some order, then the exit. The sender reaches
    # the first relay, and the second relay fails to dial the exit.
    let failed = newFuture[PeerId]("test.relayDialFailure")
    for ctx in contexts[1 .. 2]:
      ctx.completeOnDialFailure(failed)
    let fromSender = nextDialFailure(contexts[0])
    let conn =
      sender.toConnection(MixDestination.exitNode(exit.peerId), "/test/dial/1").get()
    defer:
      await conn.close()
    await conn.writeLp(@[1'u8]).wait(2.seconds)
    check (await failed.wait(5.seconds)) == exit.peerId
    check not await fromSender.withTimeout(200.milliseconds)
