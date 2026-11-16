# SPDX-License-Identifier: Apache-2.0 OR MIT
{.used.}

import std/strutils
import chronos, results, metrics
import libp2p/switch
import libp2p/stream/connection
import libp2p_mix
import
  libp2p_mix/[mix_protocol, spam_protection, cover_traffic, mix_metrics, delay_strategy]
import libp2p_mix/surb_store
import ../utils
import ../tools/[unittest, lifecycle, crypto]

type AsyncProofs = ref object of SpamProtection
  generated, verified: int
  unavailable, blocked, pending, cancelled: bool
  proofGate: AsyncEvent
  coverEpochs: seq[uint64]

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

const ReplyCodec = "/mix/test/reply/1.0.0"

const ReplyParams = MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8))

proc setupSender(
    provider: AsyncProofs, surbStore: SurbStore = nil
): tuple[nodes: seq[MixProtocol], destination: MixDestination] =
  ## Builds five nodes that are not started. The first node is the sender, with
  ## `provider` and `surbStore`. A blocked `provider` holds a send in
  ## `sendPacket`, after the send registered its reply credentials.
  let infos = MixNodeInfo.generateRandomMany(5, rng())
  var nodes: seq[MixProtocol]
  for i, info in infos:
    let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
    let proofs =
      if i == 0:
        provider
      else:
        AsyncProofs(proofSize: 1)
    let node = MixProtocol.new(
      info,
      sw,
      spamProtection = Opt.some(SpamProtection(proofs)),
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
      surbStore = (if i == 0: surbStore else: nil),
    )
    node.nodePool.add(infos.includeAllExcept(info))
    sw.mount(node)
    nodes.add(node)
  nodes[0].registerDestReadBehavior(ReplyCodec, readLp(32))
  (nodes, MixDestination.exitNode(infos[4].peerId))

proc outcome(write: Future[void]): Future[string] {.async.} =
  ## How `write` ends: an empty string, or the name and the message of its
  ## error. `join` does not cancel `write`, so a write that nothing ends gives
  ## "pending".
  if not await write.join().withTimeout(2.seconds):
    return "pending"
  if write.cancelled:
    return "cancelled"
  if write.failed:
    return $write.error.name & ": " & write.error.msg
  ""

suite "Asynchronous proof provider":
  asyncTeardown:
    checkTrackers()

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

  asyncTest "a pending write refuses a second write":
    let provider = AsyncProofs(proofSize: 1, blocked: true)
    let (nodes, destination) = setupSender(provider)
    startAndDeferStop(nodes)
    let conn = nodes[0].toConnection(destination, ReplyCodec, ReplyParams).tryGet()
    defer:
      await conn.close()

    let sending = conn.writeLp(@[1.byte, 2, 3])
    checkUntilTimeout:
      provider.pending

    check "supports a single write" in await outcome(conn.writeLp(@[4.byte, 5, 6]))
    await sending.cancelAndWait()

  asyncTest "a cancel of a pending write releases its reply credentials":
    let provider = AsyncProofs(proofSize: 1, blocked: true)
    let (nodes, destination) = setupSender(provider)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let conn = sender.toConnection(destination, ReplyCodec, ReplyParams).tryGet()
    defer:
      await conn.close()

    let sending = conn.writeLp(@[1.byte, 2, 3])
    checkUntilTimeout:
      provider.pending
    check sender.surbCredsLen == 1

    await sending.cancelAndWait()
    check:
      provider.cancelled
      sender.surbCredsLen == 0

  asyncTest "a close fails a pending write and releases its reply credentials":
    let provider = AsyncProofs(proofSize: 1, blocked: true)
    let (nodes, destination) = setupSender(provider)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let conn = sender.toConnection(destination, ReplyCodec, ReplyParams).tryGet()

    let sending = conn.writeLp(@[1.byte, 2, 3])
    checkUntilTimeout:
      provider.pending
    check sender.surbCredsLen == 1

    await conn.close()
    check:
      "LPStreamClosedError" in await outcome(sending)
      provider.cancelled
      sender.surbCredsLen == 0

  asyncTest "a stop fails a pending write and releases its reply credentials":
    let provider = AsyncProofs(proofSize: 1, blocked: true)
    let (nodes, destination) = setupSender(provider)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let conn = sender.toConnection(destination, ReplyCodec, ReplyParams).tryGet()
    defer:
      await conn.close()

    let sending = conn.writeLp(@[1.byte, 2, 3])
    checkUntilTimeout:
      provider.pending
    check sender.surbCredsLen == 1

    await sender.stop()
    check:
      "mix protocol has stopped" in await outcome(sending)
      provider.cancelled
      sender.surbCredsLen == 0

  asyncTest "a stop fails a pending fire-and-forget write":
    let provider = AsyncProofs(proofSize: 1, blocked: true)
    let (nodes, destination) = setupSender(provider)
    startAndDeferStop(nodes)
    let sender = nodes[0]
    let conn = sender.toConnection(destination, ReplyCodec).tryGet()
    defer:
      await conn.close()

    let sending = conn.writeLp(@[1.byte, 2, 3])
    checkUntilTimeout:
      provider.pending

    await sender.stop()
    check:
      "mix protocol has stopped" in await outcome(sending)
      provider.cancelled

  asyncTest "after a restart a send works and its reply credentials expire":
    let provider = AsyncProofs(proofSize: 1)
    let store = SurbStore.new(ttl = 50.milliseconds, purgeInterval = 10.milliseconds)
    let (nodes, destination) = setupSender(provider, surbStore = store)
    startAndDeferStop(nodes)
    let sender = nodes[0]

    await sender.stop()
    await sender.start()

    let conn = sender.toConnection(destination, ReplyCodec, ReplyParams).tryGet()
    defer:
      await conn.close()
    await conn.writeLp(@[1.byte, 2, 3]).wait(5.seconds)
    check provider.generated == 1
    # No reply comes, so only the purge loop of the store removes the credentials.
    checkUntilTimeout:
      sender.surbCredsLen == 0
