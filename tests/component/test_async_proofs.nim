# SPDX-License-Identifier: Apache-2.0 OR MIT
{.used.}

import chronos, results, metrics
import libp2p/switch
import libp2p/stream/connection
import libp2p_mix
import
  libp2p_mix/[mix_protocol, spam_protection, cover_traffic, mix_metrics, delay_strategy]
import ../utils
import ../tools/[unittest, lifecycle, crypto, host_pool]

type AsyncProofs = ref object of SpamProtection
  generated, verified: int
  unavailable, blocked, pending, cancelled: bool
  proofGate: AsyncEvent
  coverEpochs: seq[uint64]

type StopOrderCoverTraffic = ref object of CoverTraffic
  provider: AsyncProofs
  stoppedBeforeProof: bool

method start(ct: StopOrderCoverTraffic) {.async: (raises: [CancelledError]).} =
  discard

method stop(ct: StopOrderCoverTraffic) {.async: (raises: []).} =
  ct.stoppedBeforeProof = ct.provider.pending

method precomputeCoverProofs(sp: AsyncProofs): bool {.gcsafe, raises: [].} =
  false

method generateProofAsync(
    sp: AsyncProofs, packet: seq[byte]
): Future[Result[ProofResult, string]] {.async: (raises: [CancelledError]).} =
  if not sp.proofGate.isNil:
    sp.pending = true
    try:
      await sp.proofGate.wait()
    except CancelledError as exc:
      sp.cancelled = true
      raise exc
    finally:
      sp.pending = false
  elif sp.blocked:
    sp.pending = true
    try:
      await sleepAsync(1.minutes)
    except CancelledError as exc:
      sp.cancelled = true
      raise exc
    finally:
      sp.pending = false
  await sleepAsync(5.milliseconds)
  if sp.unavailable:
    return err("backend unavailable")
  inc sp.generated
  return ok(ProofResult(proof: @[packet[0]]))

method generateProofAsync(
    sp: AsyncProofs, packet: seq[byte], epoch: uint64
): Future[Result[ProofResult, string]] {.async: (raises: [CancelledError]).} =
  sp.coverEpochs.add(epoch)
  return await sp.generateProofAsync(packet)

method verifyProofAsync(
    sp: AsyncProofs, proof, packet: seq[byte]
): Future[Result[bool, string]] {.async: (raises: [CancelledError]).} =
  await sleepAsync(5.milliseconds)
  inc sp.verified
  return ok(proof == @[packet[0]])

suite "Asynchronous proof provider":
  asyncTest "cover proofs overlap hold and epoch-crossed packets are discarded":
    let infos = MixNodeInfo.generateRandomMany(3, rng())
    let sw = createSwitch(infos[0].multiAddr, Opt.some(infos[0].libp2pPrivKey))
    let provider = AsyncProofs(proofSize: 1, proofGate: newAsyncEvent())
    let ct = ConstantRateCoverTraffic.new(
      totalSlots = 2,
      epochDuration = 20.milliseconds,
      enablePrecomputation = true,
      useInternalEpochTimer = false,
    )
    let node = MixProtocol.new(
      infos[0],
      sw,
      spamProtection = Opt.some(SpamProtection(provider)),
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
      coverTraffic = Opt.some(CoverTraffic(ct)),
    )
    for info in infos[1 .. ^1]:
      node.nodePool.add(info.toMixPubInfo())

    var sent = 0
    ct.setCoverPacketSender(
      proc(
          peerId: PeerId, multiAddr: MultiAddress, packet: seq[byte], epoch: uint64
      ): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
        inc sent
        return ok()
    )
    ct.setSendDelaySampler(
      proc(): Delay {.gcsafe, raises: [].} =
        Delay(200)
    )
    ct.onEpochChange(7)

    let emission = ct.emitCoverPacket()
    await sleepAsync(250.milliseconds)
    check provider.pending
    check provider.coverEpochs == @[7'u64]

    ct.onEpochChange(8)
    provider.proofGate.fire()
    await emission
    check sent == 0

    let built = (await node.buildCoverPacket(9)).tryGet()
    provider.proofGate = newAsyncEvent()
    ct.onEpochChange(9)
    ct.slotPool.addPacket(
      CoverPacket(
        packet: built.packet,
        firstHopPeerId: built.firstHopPeerId,
        firstHopAddr: built.firstHopAddr,
      )
    )

    let prebuiltEmission = ct.emitCoverPacket()
    await sleepAsync(250.milliseconds)
    check provider.pending
    check provider.coverEpochs == @[7'u64, 9'u64]

    ct.onEpochChange(10)
    provider.proofGate.fire()
    await prebuiltEmission
    check sent == 0

    provider.cancelled = false
    provider.proofGate = newAsyncEvent()
    ct.onEpochChange(11)
    await ct.start()
    checkUntilTimeout:
      provider.pending
    await ct.stop()
    check provider.cancelled
    check not provider.pending

  asyncTest "cover proof completed within the epoch is sent":
    let infos = MixNodeInfo.generateRandomMany(3, rng())
    let sw = createSwitch(infos[0].multiAddr, Opt.some(infos[0].libp2pPrivKey))
    let provider = AsyncProofs(proofSize: 1)
    let ct = ConstantRateCoverTraffic.new(
      totalSlots = 2,
      epochDuration = 1.seconds,
      enablePrecomputation = false,
      useInternalEpochTimer = false,
    )
    let node = MixProtocol.new(
      infos[0],
      sw,
      spamProtection = Opt.some(SpamProtection(provider)),
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
      coverTraffic = Opt.some(CoverTraffic(ct)),
    )
    for info in infos[1 .. ^1]:
      node.nodePool.add(info.toMixPubInfo())

    var sentPacket: seq[byte]
    ct.setCoverPacketSender(
      proc(
          peerId: PeerId, multiAddr: MultiAddress, packet: seq[byte], epoch: uint64
      ): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
        sentPacket = packet
        return ok()
    )
    ct.onEpochChange(7)

    await ct.emitCoverPacket()

    check provider.coverEpochs == @[7'u64]
    check provider.generated == 1
    let (packet, proof) =
      extractProofFromPacket(sentPacket, SpamProtection(provider)).tryGet()
    check proof == @[packet[0]]

  asyncTest "cover precomputation spends no proofs; routing awaits per-hop proofs":
    let infos = MixNodeInfo.generateRandomMany(5, rng())
    var nodes: seq[MixProtocol]
    var providers: seq[AsyncProofs]
    for info in infos:
      let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
      let provider = AsyncProofs(proofSize: 1)
      let node = MixProtocol.new(
        info,
        sw,
        spamProtection = Opt.some(SpamProtection(provider)),
        delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
      )
      for other in infos:
        if other.peerId != info.peerId:
          node.nodePool.add(other.toMixPubInfo())
      sw.mount(node)
      nodes.add(node)
      providers.add(provider)
    startAndDeferStop(nodes)
    let received = mix_cover_received.value()
    let cover = (await nodes[0].buildCoverPacket()).tryGet()
    check providers[0].generated == 0
    check cover.proofToken.len == 0
    check (
      await nodes[0].sendCoverPacket(
        cover.firstHopPeerId, cover.firstHopAddr, cover.packet
      )
    ).isOk
    checkUntilTimeout:
      mix_cover_received.value() > received
    var generated, verified: int
    for sp in providers:
      generated += sp.generated
      verified += sp.verified
    check generated == 3
    check verified == 3
    providers[0].unavailable = true
    let next = (await nodes[0].buildCoverPacket()).tryGet()
    check (
      await nodes[0].sendCoverPacket(
        next.firstHopPeerId, next.firstHopAddr, next.packet
      )
    ).isErr
    check providers[0].generated == 1

    providers[0].unavailable = false
    providers[0].blocked = true
    let conn = nodes[0]
      .toConnection(MixDestination.exitNode(infos[4].peerId), "/mix/test/cancel/1.0.0")
      .tryGet()
    defer:
      await conn.close()
    let sending = conn.writeLp(@[1.byte, 2, 3])
    checkUntilTimeout:
      providers[0].pending
    await sending.cancelAndWait()
    check providers[0].cancelled
    check not providers[0].pending

  asyncTest "a pending request refuses a second write and releases its reply credentials on a cancel, a close or a stop":
    ## The provider blocks inside `sendPacket`, after the reply credentials
    ## are registered. A cancel and a close must both release them, and
    ## `write` refuses a second write on a pending request.
    var infos = MixNodeInfo.generateRandomMany(5, rng())
    for info in infos.mitems:
      info.multiAddr = MultiAddress.init("/ip4/127.0.0.1/tcp/0").tryGet()
    var nodes: seq[MixProtocol]
    let provider = AsyncProofs(proofSize: 1, blocked: true)
    let cover = StopOrderCoverTraffic(provider: provider, slotPool: SlotPool.new(100))
    for i, info in infos:
      let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
      let sp =
        if i == 0:
          provider
        else:
          AsyncProofs(proofSize: 1)
      let node = MixProtocol.new(
        info,
        sw,
        pool = HostPool.new(),
        spamProtection = Opt.some(SpamProtection(sp)),
        coverTraffic =
          (if i == 0: Opt.some(CoverTraffic(cover)) else: Opt.none(CoverTraffic)),
        delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
      )
      for other in infos:
        if other.peerId != info.peerId:
          node.hostPool.addPeer(other.toMixPubInfo())
      sw.mount(node)
      nodes.add(node)
    startAndDeferStop(nodes)
    # Each host store gets the listen addresses, so the send after the restart
    # reaches the first hop.
    for node in nodes:
      node.setLocalMultiAddr(node.switch.peerInfo.addrs[0]).expect("bound address")
    for node in nodes:
      for other in nodes:
        if other != node:
          node.hostPool.addPeer(other.localMixPubInfo())
    let sender = nodes[0]
    let destination = MixDestination.exitNode(infos[4].peerId)
    let params = MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8))
    sender.registerDestReadBehavior("/mix/test/cancel/1.0.0", readLp(32))
    sender.registerDestReadBehavior("/mix/test/close/1.0.0", readLp(32))

    let connToCancel =
      sender.toConnection(destination, "/mix/test/cancel/1.0.0", params).tryGet()
    defer:
      await connToCancel.close()
    let sending = connToCancel.writeLp(@[1.byte, 2, 3])
    checkUntilTimeout:
      provider.pending
    check sender.surbCredsLen == 1
    expect LPStreamError:
      await connToCancel.writeLp(@[4.byte, 5, 6])
    await sending.cancelAndWait()
    check provider.cancelled
    check sender.surbCredsLen == 0

    provider.cancelled = false
    let connToClose =
      sender.toConnection(destination, "/mix/test/close/1.0.0", params).tryGet()
    let writing = connToClose.writeLp(@[1.byte, 2, 3])
    checkUntilTimeout:
      provider.pending
    check sender.surbCredsLen == 1
    await connToClose.close()
    expect LPStreamClosedError:
      await writing.wait(2.seconds)
    check provider.cancelled
    check sender.surbCredsLen == 0
    expect LPStreamClosedError:
      await connToClose.writeLp(@[4.byte, 5, 6])
    check sender.surbCredsLen == 0

    # Protocol stop cancels the same in-flight send, including its proof work.
    provider.cancelled = false
    let connToStop =
      sender.toConnection(destination, "/mix/test/close/1.0.0", params).get()
    defer:
      await connToStop.close()
    let stoppedWrite = connToStop.writeLp(@[7.byte, 8, 9])
    checkUntilTimeout:
      provider.pending
    await sender.stop()
    check cover.stoppedBeforeProof
    expect LPStreamError:
      await stoppedWrite
    check provider.cancelled
    check sender.surbCredsLen == 0
    await sender.start()
    provider.blocked = false
    let connAfterRestart =
      sender.toConnection(destination, "/mix/test/close/1.0.0", params).get()
    await connAfterRestart.writeLp(@[1.byte, 2, 3]).wait(5.seconds)
    await connAfterRestart.close()
    check sender.surbCredsLen == 0

  asyncTest "protocol stop closes the cached hop streams":
    let nodes = await startTestMixNodes(5)
    defer:
      await stopNodes(nodes)
    let sender = nodes[0]
    let echo = EchoProtocol.new()
    await echo.start()
    nodes[^1].switch.mount(echo)
    for node in nodes:
      node.registerDestReadBehavior(echo.codec, readLp(1024))
    let conn = sender
      .toConnection(
        nodes[^1].switch.toMixDestination(),
        echo.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8)),
      )
      .get()
    await conn.writeLp(@[7'u8]).wait(5.seconds)
    check (await conn.readLp(1024).wait(5.seconds)) == @[7'u8]
    await conn.close()
    check outgoingMixStreams(sender.switch).len > 0
    await sender.stop()
    check outgoingMixStreams(sender.switch).len == 0
