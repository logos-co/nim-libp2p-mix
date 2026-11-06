# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronicles, chronos, sequtils, results, sets
import std/[strformat, tables], metrics
import
  ./[
    curve25519, delay, padding, mix_message, mix_node, sphinx, serialization,
    tag_manager, mix_metrics, exit_layer, multiaddr, exit_connection, spam_protection,
    delay_strategy, pool, cover_traffic, surb_store,
  ]
import libp2p/protocols/protocol
import libp2p/stream/[connection, lpstream]
import libp2p/[switch, multicodec, peerinfo, varint]
import libp2p/crypto/crypto

export pool
export SurbStore, SurbSession

when defined(enable_mix_benchmarks):
  import ./benchmark
  from times import getTime, toUnixFloat, `-`, initTime, `$`, inMilliseconds, Time
logScope:
  topics = "mix_protocol"

when defined(libp2p_mix_experimental_exit_is_dest):
  {.warning: "experimental support for mix exit == destination is enabled!".}

const MixProtocolID* = "/mix/1.0.0"

const CoverTrafficCodec* = "/mix/cover/1.0.0"
  ## Reserved codec for cover traffic packets. Cover packets use this codec
  ## so the exit node can identify and silently discard returning cover traffic.

const DefaultHopBackoff* = chronos.minutes(1)
  ## How long a first hop that failed a dial is not selected as the first hop.

type
  HopDial = Future[Connection].Raising([DialFailedError, CancelledError])
    ## A dial of a hop, as `switch.dial` returns it.

  OtherAddressDialError = object of DialFailedError
    ## A caller of `getConn` waited for a dial of another address, and it failed.
    ## It is no failure of the address of the caller.

func isCoverTraffic*(msg: MixMessage): bool =
  ## Returns true if the message is a cover traffic packet.
  msg.codec == CoverTrafficCodec

## Mix Protocol defines a decentralized anonymous message routing layer for libp2p networks.
## It enables sender anonymity by routing each message through a decentralized mix overlay
## network composed of participating libp2p nodes, known as mix nodes. Each message is
## routed independently in a stateless manner, allowing other libp2p protocols to selectively
## anonymize messages without modifying their core protocol behavior.
type MixProtocol* = ref object of LPProtocol
  mixNodeInfo: MixNodeInfo
  switch*: Switch
  nodePool*: MixNodePool
  tagManager: TagManager
  exitLayer: ExitLayer
  rng: Rng
  surbStore: SurbStore
    ## Reply credentials for SURBs this node has issued. Expires entries whose
    ## reply never arrives; see surb_store.nim.
  destReadBehaviors: TableRef[string, DestReadBehavior]
  connPool: Table[PeerId, Connection]
  dialing: Table[PeerId, tuple[dial: HopDial, addrs: seq[MultiAddress]]]
    ## The dial in flight for each hop. Concurrent callers of getConn await
    ## the same dial and share its result.
    ## `addrs` are the addresses that the dial uses.
    ## The library dials through the switch of libp2p.
    ## The switch has one dial lock and one set of connections for each peer.
    ## So a second dial of the peer at other addresses waits for the first dial.
    ## A forward and a reply dial the address that the sender of the packet gave.
    ## So a caller can wait for a dial of an address that it did not select.
  backedOffUntil: Table[PeerId, Moment]
    ## The moment until which a first hop that failed a dial is not the first hop.
  hopBackoff: Duration
  spamProtection: Opt[SpamProtection]
  delayStrategy: DelayStrategy
  coverTraffic*: Opt[CoverTraffic]
  ongoingMixMessages: Table[uint64, Future[void]]
    ## In-flight handleMixMessages futures, cancelled on stop. Keyed so
    ## removal on completion is O(1).
  nextMixMessageId: uint64

proc hasDestReadBehavior*(mixProto: MixProtocol, codec: string): bool =
  return mixProto.destReadBehaviors.hasKey(codec)

proc registerDestReadBehavior*(
    mixProto: MixProtocol, codec: string, behavior: DestReadBehavior
) =
  mixProto.destReadBehaviors[codec] = behavior

proc localMixPubInfo*(mixProto: MixProtocol): MixPubInfo =
  mixProto.mixNodeInfo.toMixPubInfo()

proc setLocalMultiAddr*(
    mixProto: MixProtocol, multiAddr: MultiAddress
): Result[void, string] {.raises: [].} =
  ## Update the multiaddr used as this node's self hop (SURBs, cover traffic)
  ## and by ``localMixPubInfo``. Must be a mix-encodable transport address
  ## without a trailing destination ``/p2p/<peerId>``; circuit-relay form is ok.
  ## Already-issued SURBs are not updated.
  discard multiAddrToBytes(mixProto.mixNodeInfo.peerId, multiAddr).valueOr:
    return err("invalid local multiaddress: " & error)
  mixProto.mixNodeInfo.multiAddr = multiAddr
  ok()

proc surbCredsLen*(mixProto: MixProtocol): int =
  mixProto.surbStore.len

proc cryptoRandomInt(rng: Rng, max: int): Result[int, string] =
  if max == 0:
    return err("Max cannot be zero.")
  let res = rng.generate(uint64) mod uint64(max)
  ok(res.int)

proc hopIsBackedOff(mixProto: MixProtocol, peerId: PeerId): bool =
  ## True while `peerId` waits out a failed dial. Only the first hop is filtered.
  ## It is the one hop this node both selects and dials.
  Moment.now() < mixProto.backedOffUntil.getOrDefault(peerId)

proc backOffHop(mixProto: MixProtocol, peerId: PeerId, failure: ref DialFailedError) =
  ## Record a failed dial of `peerId`, and delete the entries whose backoff ended.
  ## An `OtherAddressDialError` records nothing.
  if failure of OtherAddressDialError:
    return
  let now = Moment.now()
  var expired: seq[PeerId]
  for backedOff, until in mixProto.backedOffUntil:
    if now >= until:
      expired.add(backedOff)
  for backedOff in expired:
    mixProto.backedOffUntil.del(backedOff)
  mixProto.backedOffUntil[peerId] = now + mixProto.hopBackoff

proc removeClosedConnections(
    mixProto: MixProtocol, failed: Connection
) {.async: (raises: []).} =
  ## Take `failed` and the streams of disconnected peers out of the pool and
  ## close them.
  var stale: seq[tuple[peerId: PeerId, conn: Connection]]
  for peerId, conn in mixProto.connPool:
    if conn == failed or not mixProto.switch.isConnected(peerId):
      stale.add((peerId, conn))
  for (peerId, _) in stale:
    mixProto.connPool.del(peerId)
  for (_, conn) in stale:
    await conn.close()

proc startDial(
    mixProto: MixProtocol, pid: PeerId, addrs: seq[MultiAddress], codecs: seq[string]
): HopDial =
  ## Start the one dial of `pid` that concurrent callers of `getConn` share, and
  ## keep it in `dialing` until it finishes.
  let dial = mixProto.switch.dial(pid, addrs, codecs)
  mixProto.dialing[pid] = (dial: dial, addrs: addrs)
  dial.addCallback(
    proc(_: pointer) {.gcsafe, raises: [].} =
      mixProto.dialing.del(pid)
      if dial.completed():
        mixProto.backedOffUntil.del(pid)
        if mixProto.started:
          mixProto.connPool[pid] = dial.value
  )
  dial

proc getConn(
    mixProto: MixProtocol,
    pid: PeerId,
    addrs: seq[MultiAddress],
    codecs: seq[string],
    failed: Connection = nil,
): Future[Connection] {.async: (raises: [DialFailedError, CancelledError]).} =
  ## Return the cached stream to `pid`, or the result of the one dial in flight.
  ## `failed` is a cached stream whose write failed. It is closed and replaced.
  if not failed.isNil:
    await mixProto.removeClosedConnections(failed)
  mixProto.connPool.withValue(pid, conn):
    return conn[]
  if not mixProto.started:
    raise newException(DialFailedError, "mix protocol is not running")
  let inFlight = mixProto.dialing.getOrDefault(pid)
  let dialOfOtherAddrs = not inFlight.dial.isNil and inFlight.addrs != addrs
  let dial =
    if inFlight.dial.isNil:
      mixProto.startDial(pid, addrs, codecs)
    else:
      inFlight.dial
  await dial.join()
  if dial.cancelled():
    # Only `stop` cancels a shared dial. A caller cancelled in `join` raises
    # before this line.
    raise newException(DialFailedError, "mix protocol stopped during the dial")
  if not mixProto.started:
    # The dial completed after the stop began. The stop closes its stream, so
    # no caller writes to it.
    raise newException(DialFailedError, "mix protocol stopped during the dial")
  if dial.failed() and dialOfOtherAddrs:
    # A caller waits for one dial at most.
    # So it does not dial its own addresses after this failure.
    let failure = dial.error
    raise newException(
      OtherAddressDialError, "a dial of other addresses failed: " & failure.msg, failure
    )
  try:
    return dial.read()
  except FuturePendingError:
    raiseAssert "join returned with the dial still pending"

proc writeLpWithRetry(
    mixProto: MixProtocol,
    c: Connection,
    pid: PeerId,
    addrs: seq[MultiAddress],
    codecs: seq[string],
    payload: seq[byte],
) {.async: (raises: [DialFailedError, LPStreamError, CancelledError]).} =
  try:
    await c.writeLp(payload)
  except LPStreamClosedError, LPStreamResetError, LPStreamRemoteClosedError,
      LPStreamConnDownError:
    let replacement = await mixProto.getConn(pid, addrs, codecs, failed = c)
    await replacement.writeLp(payload)

proc writeLp(
    mixProto: MixProtocol,
    pid: PeerId,
    addrs: seq[MultiAddress],
    codecs: seq[string],
    payload: seq[byte],
) {.async: (raises: [DialFailedError, LPStreamError, CancelledError]).} =
  let c = await mixProto.getConn(pid, addrs, codecs)
  await mixProto.writeLpWithRetry(c, pid, addrs, codecs, payload)

proc generateAndAppendProof(
    mixProto: MixProtocol,
    packet: seq[byte],
    label: string,
    epoch: Opt[uint64] = Opt.none(uint64),
): Future[Result[tuple[packet: seq[byte], proofToken: seq[byte]], string]] {.
    async: (raises: [CancelledError])
.} =
  ## Generate spam protection proof and append it to the packet.
  ## Returns the packet with proof appended and an opaque proof token
  ## for proof slot tracking.
  let spamProtection = mixProto.spamProtection.valueOr:
    return ok((packet, newSeq[byte]()))

  let bindingData = packet
  let generated =
    if epoch.isSome:
      await spamProtection.generateProofAsync(bindingData, epoch.get())
    else:
      await spamProtection.generateProofAsync(bindingData)
  let proofResult = generated.mapErr(
    proc(e: string): string =
      mix_messages_error.inc(labelValues = [label, "SPAM_PROOF_GEN_FAILED"])
      fmt"Failed to generate spam protection proof: {e}"
  ).valueOr:
    return err(error)

  if proofResult.proof.len != spamProtection.proofSize:
    return err(
      "Spam protection provider returned proof size " & $proofResult.proof.len &
        ", expected " & $spamProtection.proofSize
    )

  let packetWithProof = appendProofToPacket(packet, proofResult.proof)
    .mapErr(
      proc(e: string): string =
        mix_messages_error.inc(labelValues = [label, "SPAM_PROOF_EMBED_FAILED"])
        fmt"Failed to append spam protection proof: {e}"
    ).valueOr:
      return err(error)

  return ok((packetWithProof, proofResult.token))

proc extractProof(
    mixProto: MixProtocol, packetWithProof: var seq[byte], label: string
): Result[tuple[sphinxPacket: seq[byte], proof: seq[byte]], string] =
  ## Extract spam protection proof from the packet without verifying.
  ## Returns the Sphinx packet and the extracted proof.

  let spamProtection = mixProto.spamProtection.valueOr:
    return ok((sphinxPacket: packetWithProof, proof: newSeq[byte](0)))

  let (packet, proofData) = extractProofFromPacket(packetWithProof, spamProtection)
    .mapErr(
      proc(e: string): string =
        mix_messages_error.inc(labelValues = [label, "SPAM_PROOF_EXTRACTION_FAILED"])
        fmt"Failed to extract spam protection proof: {e}"
    ).valueOr:
      return err(error)

  ok((sphinxPacket: packet, proof: proofData))

proc verifyProof(
    mixProto: MixProtocol, sphinxPacket: seq[byte], proof: seq[byte], label: string
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  ## Verify a previously extracted spam protection proof.
  let spamProtection = mixProto.spamProtection.valueOr:
    return ok()

  let bindingData = sphinxPacket

  let verifyResult = (await spamProtection.verifyProofAsync(proof, bindingData)).valueOr:
    mix_messages_error.inc(labelValues = [label, "SPAM_PROOF_VERIFY_ERROR"])
    return err(fmt"Spam protection proof verification error: {error}")

  if not verifyResult:
    mix_messages_error.inc(labelValues = [label, "SPAM_PROOF_INVALID"])
    return err("Spam protection proof verification failed")

  trace "Spam protection proof verified successfully"
  return ok()

method handleMixMessages*(
    mixProto: MixProtocol,
    fromPeerId: PeerId,
    receivedBytes: sink seq[byte],
    metadataBytes: sink seq[byte],
) {.base, async: (raises: [LPStreamError, CancelledError]).} =
  when defined(enable_mix_benchmarks):
    let startTime = getTime()

    if metadataBytes.len == 0:
      mix_messages_error.inc(labelValues = ["Intermediate/Exit", "NO_DATA"])
      return # No data, end of stream

  if receivedBytes.len == 0:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "NO_DATA"])
    return # No data, end of stream

  # Step 1: Extract spam proof
  # Note: extractProof takes var to enable zero-copy truncation
  let (sphinxBytes, spamProof) = mixProto.extractProof(
    receivedBytes, "Intermediate/Exit"
  ).valueOr:
    error "Spam proof extraction failed", err = error
    return

  # Step 2: Deserialize and check replay
  let sphinxPacket = SphinxPacket.deserialize(sphinxBytes).valueOr:
    error "Sphinx deserialization failed", err = error
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_SPHINX"])
    return

  let (isReplay, sharedSecret) = checkReplay(
    sphinxPacket, mixProto.mixNodeInfo.mixPrivKey, mixProto.tagManager
  ).valueOr:
    error "Replay check failed", err = error
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_SPHINX"])
    return

  if isReplay:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "DUPLICATE"])
    return

  # Step 3: Verify spam proof
  # Only done after replay check passes to avoid wasting cycles on duplicates
  (await mixProto.verifyProof(sphinxBytes, spamProof, "Intermediate/Exit")).isOkOr:
    error "Spam protection verification failed", err = error
    return

  # Step 4: Full Sphinx processing
  # Reuse the shared secret computed in step 2 to avoid duplicate EC multiplication
  let processedSP = processSphinxPacket(
    sphinxPacket,
    mixProto.mixNodeInfo.mixPrivKey,
    mixProto.tagManager,
    Opt.some(sharedSecret),
  ).valueOr:
    error "Failed to process Sphinx packet", err = error
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_SPHINX"])
    return

  when defined(enable_mix_benchmarks):
    let metadata = Metadata.deserialize(metadataBytes)

  case processedSP.status
  of Exit:
    mix_messages_recvd.inc(labelValues = ["Exit"])

    # This is the exit node, forward to destination
    let unpaddedMsg = removePadding(processedSP.messageChunk).valueOr:
      error "Unpadding message failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_SPHINX"])
      return

    let deserialized = MixMessage.deserialize(unpaddedMsg).valueOr:
      error "Deserialization failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_SPHINX"])
      return

    if isCoverTraffic(deserialized):
      trace "Cover packet received (loop), discarding",
        peerId = mixProto.mixNodeInfo.peerId
      mix_cover_received.inc()
      mixProto.coverTraffic.withValue(ct):
        ct.onCoverReceived()
      return

    let (surbs, message) = extractSURBs(deserialized.message).valueOr:
      error "Extracting surbs from payload failed", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_MSG_SURBS"])
      return

    trace "Exit node - Received mix message",
      peerId = mixProto.mixNodeInfo.peerId, codec = deserialized.codec

    when defined(enable_mix_benchmarks):
      benchmarkLog "Exit",
        mixProto.switch.peerInfo.peerId,
        startTime,
        metadata,
        Opt.some(fromPeerId),
        Opt.none(PeerId)

    await mixProto.exitLayer.onMessage(
      deserialized.codec, message, processedSP.destination, surbs
    )

    mix_messages_forwarded.inc(labelValues = ["Exit"])
  of Reply:
    trace "# Reply", id = processedSP.id

    # Expired credentials are invisible here even if no sweep has run yet.
    let connCred = mixProto.surbStore.get(processedSP.id).valueOr:
      mix_messages_error.inc(labelValues = ["Sender/Reply", "NO_CONN_FOUND"])
      return

    let reply = processReply(
      connCred.surbKey, connCred.surbSecret, processedSP.delta_prime
    ).valueOr:
      error "could not process reply", id = processedSP.id
      mix_messages_error.inc(labelValues = ["Reply", "INVALID_CREDS"])
      return

    # Each SURB is single-use; other blocks can still deliver their replies.
    mixProto.surbStore.release(processedSP.id)

    let unpaddedMsg = removePadding(reply).valueOr:
      error "Unpadding message failed", err = error
      mix_messages_error.inc(labelValues = ["Reply", "INVALID_SPHINX"])
      return

    let deserialized = MixMessage.deserialize(unpaddedMsg).valueOr:
      error "Deserialization failed", err = error
      mix_messages_error.inc(labelValues = ["Reply", "INVALID_SPHINX"])
      return

    when defined(enable_mix_benchmarks):
      benchmarkLog "Reply",
        mixProto.switch.peerInfo.peerId,
        startTime,
        metadata,
        Opt.some(fromPeerId),
        Opt.none(PeerId)

    await connCred.incoming.put(deserialized.message)
  of Intermediate:
    trace "Intermediate node processing",
      peerId = mixProto.mixNodeInfo.peerId, multiAddr = mixProto.mixNodeInfo.multiAddr
    mix_messages_recvd.inc(labelValues = ["Intermediate"])

    # Claim a slot for forwarding (Mix Cover Traffic spec §6.4)
    var claimEpoch: uint64
    mixProto.coverTraffic.withValue(ct):
      let claim = ct.slotPool.claimSlot()
      if not claim.success:
        warn "Slot exhaustion, dropping forwarded packet"
        mix_messages_error.inc(labelValues = ["Intermediate", "SLOT_EXHAUSTED"])
        mix_slot_claim_rejected.inc(labelValues = ["forward"])
        return
      claimEpoch = ct.slotPool.epoch
      # Reclaim proof token from discarded cover packet for messageId reuse
      if claim.reclaimedToken.len > 0:
        mixProto.spamProtection.withValue(sp):
          sp.reclaimProofToken(claim.reclaimedToken)

    template refundSlot(): untyped =
      mixProto.coverTraffic.withValue(ct):
        ct.slotPool.unclaimSlot(claimEpoch)

    let actualDelay = mixProto.delayStrategy.generateForIntermediate(processedSP.delay)
    trace "Computed delay", encodedDelay = processedSP.delay, actualDelay

    # Forward to next hop
    let nextHopBytes = processedSP.nextHop.get()

    let (nextPeerId, nextAddr) = bytesToMultiAddr(nextHopBytes).valueOr:
      trace "Failed to convert bytes to multiaddress", err = error
      mix_messages_error.inc(labelValues = ["Intermediate", "INVALID_DEST"])
      refundSlot()
      return

    when defined(enable_mix_benchmarks):
      benchmarkLog "Intermediate",
        mixProto.switch.peerInfo.peerId,
        startTime,
        metadata,
        Opt.some(fromPeerId),
        Opt.some(nextPeerId)

    # Per-hop spam protection: generate the fresh proof while the packet is
    # being held. When using SpamProtectionDelayStrategy (or similar) with
    # exponential delays, a lower sampling floor can be applied so this overlap
    # does not collapse short samples into a fixed processing-time spike.
    let proofGenStartTime = Moment.now()
    let delayFut = sleepAsync(actualDelay.toDuration)

    # proofGenTimeMs is captured at proof completion, inside the closure, so it
    # measures proof cost alone — not max(proof, delay) as after allFutures.
    var proofGenTimeMs: int64
    let proofGenFut = (
      proc(): Future[Result[tuple[packet: seq[byte], proofToken: seq[byte]], string]] {.
          async: (raises: [CancelledError])
      .} =
        let res = await mixProto.generateAndAppendProof(
          processedSP.serializedSphinxPacket, "Intermediate"
        )
        proofGenTimeMs = (Moment.now() - proofGenStartTime).milliseconds
        return res
    )()

    defer:
      await cancelAndWait(proofGenFut, delayFut)
    await allFutures(proofGenFut, delayFut)

    mixProto.spamProtection.withValue(sp):
      if proofGenTimeMs > actualDelay.int64:
        warn "Proof generation time exceeds sampled delay",
          proofGenTimeMs,
          sampledDelay = actualDelay,
          hint = "Increase the minimum delay floor or reduce proof generation time"

    let (outgoingPacket, proofToken) = (await proofGenFut).valueOr:
      error "Failed to generate spam protection proof for next hop", err = error
      refundSlot()
      return

    # Only a failed first dial proves the packet never left this node, so its
    # slot can be refunded and its messageId reused. After any write attempt the
    # next hop may hold the proof, and reissuing the messageId in this epoch
    # would be an RLN double-signal.
    let conn =
      try:
        await mixProto.getConn(nextPeerId, @[nextAddr], @[MixProtocolID])
      except DialFailedError as exc:
        # A dial that the stop ended is not a failure of the hop.
        if mixProto.started:
          error "Failed to dial next hop: ", err = exc.msg
          mix_messages_error.inc(labelValues = ["Intermediate", "DIAL_FAILED"])
        if proofToken.len > 0:
          mixProto.spamProtection.withValue(sp):
            sp.reclaimProofToken(proofToken)
        refundSlot()
        return

    try:
      when defined(enable_mix_benchmarks):
        await mixProto.writeLpWithRetry(
          conn, nextPeerId, @[nextAddr], @[MixProtocolID], metadataBytes
        )
      await mixProto.writeLpWithRetry(
        conn, nextPeerId, @[nextAddr], @[MixProtocolID], outgoingPacket
      )
      mix_messages_forwarded.inc(labelValues = ["Intermediate"])
    except CancelledError as exc:
      raise exc
    except DialFailedError as exc:
      # A dial that the stop ended is not a failure of the hop.
      if mixProto.started:
        error "Failed to dial next hop: ", err = exc.msg
        mix_messages_error.inc(labelValues = ["Intermediate", "DIAL_FAILED"])
    except LPStreamError as exc:
      error "Failed to write to next hop: ", err = exc.msg
      mix_messages_error.inc(labelValues = ["Intermediate", "DIAL_FAILED"])
  of Duplicate:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "DUPLICATE"])
  of ReplayCacheFull:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "REPLAY_CACHE_FULL"])
  of InvalidMAC:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_MAC"])

proc proofSize(sp: Opt[SpamProtection]): int =
  ## Helper to get proof size from optional spam protection.
  ## Returns 0 if spam protection is None.
  let spamProtection = sp.valueOr:
    return 0
  return spamProtection.proofSize

proc runMixMessage(
    mixProto: MixProtocol,
    fromPeerId: PeerId,
    receivedBytes: sink seq[byte],
    metadataBytes: sink seq[byte],
) {.async: (raises: []).} =
  try:
    await mixProto.handleMixMessages(fromPeerId, receivedBytes, metadataBytes)
  except CancelledError:
    trace "Handling mix message cancelled", fromPeerId
  except LPStreamError as e:
    error "Error handling mix message", fromPeerId, err = e.msg

proc spawnMixMessage(
    mixProto: MixProtocol,
    fromPeerId: PeerId,
    receivedBytes: sink seq[byte],
    metadataBytes: sink seq[byte],
) =
  ## Spawns a handleMixMessages task, tracks its future in `ongoingMixMessages`,
  ## and removes it from the list when it finishes.
  if not mixProto.started:
    return
  let id = mixProto.nextMixMessageId
  mixProto.nextMixMessageId.inc()
  let fut = runMixMessage(mixProto, fromPeerId, receivedBytes, metadataBytes)
  mixProto.ongoingMixMessages[id] = fut
  fut.addCallback(
    proc(_: pointer) {.gcsafe, raises: [].} =
      mixProto.ongoingMixMessages.del(id)
  )

proc handleMixNodeConnection(
    mixProto: MixProtocol, conn: Connection
) {.async: (raises: [LPStreamError, CancelledError]).} =
  defer:
    await conn.close()

  while not conn.atEof:
    var metadataBytes = newSeqUninit[byte](0)
    when defined(enable_mix_benchmarks):
      metadataBytes = await conn.readLp(MetadataSize)

    # Calculate maximum wire packet size including spam protection proof
    let maxWireSize = PacketSize + mixProto.spamProtection.proofSize()
    let receivedBytes = await conn.readLp(maxWireSize)
    mixProto.spawnMixMessage(conn.peerId, receivedBytes, metadataBytes)

proc getMaxMessageSizeForCodec*(
    codec: string, numberOfSurbs: uint8 = 0
): Result[int, string] =
  ## Computes the maximum payload size (in bytes) available for a message when encoded  
  ## with the given `codec`, optionally including space for the chosen number of surbs.  
  ## Returns an error if the codec + surb overhead exceeds the data capacity.  
  let totalLen = serializedLen(codec, 0) + SurbLenSize + (int(numberOfSurbs) * SurbSize)
  if totalLen > DataSize:
    return err("cannot encode messages for this codec")
  return ok(DataSize - totalLen)

proc drawUsable(
    mixProto: MixProtocol, peerIds: var seq[PeerId]
): Result[MixPubInfo, string] {.gcsafe, raises: [].} =
  ## Draws peers from `peerIds` until the pool has a hop address for one, and
  ## removes each peer that it draws. So each peer that a path can use has the
  ## same chance, and a peer with no hop address keeps its mix key.
  while true:
    let drawn = mixProto.rng.pick(peerIds, 1).valueOr:
      return err("Ran out of usable mix nodes")
    peerIds.del(peerIds.find(drawn[0]))
    mixProto.nodePool.get(drawn[0]).withValue(mixPubInfo):
      return ok(mixPubInfo)

method buildSurb*(
    mixProto: MixProtocol, id: SURBIdentifier, destPeerId: PeerId, exitPeerId: PeerId
): Result[SURB, string] {.base, gcsafe, raises: [].} =
  var
    publicKeys: seq[FieldElement] = @[]
    hops: seq[Hop] = @[]
    delays: seq[Delay] = @[]

  if mixProto.nodePool.len < PathLength:
    return err("No. of public mix nodes less than path length")

  # Remove exit and dest node from nodes to consider for surbs
  var poolPeerIds =
    mixProto.nodePool.peerIds().filterIt(it != exitPeerId and it != destPeerId)

  # Select L mix nodes at random
  for i in 0 ..< PathLength:
    let (peerId, multiAddr, mixPubKey, hopDelay) =
      if i < PathLength - 1:
        let mixPubInfo = mixProto.drawUsable(poolPeerIds).valueOr:
          return err(error)
        debug "Selected mix node for surbs: ", indexInPath = i
        (
          mixPubInfo.peerId,
          mixPubInfo.multiAddr,
          mixPubInfo.mixPubKey,
          mixProto.delayStrategy.generateForEntry(),
        )
      else:
        (
          mixProto.mixNodeInfo.peerId, mixProto.mixNodeInfo.multiAddr,
          mixProto.mixNodeInfo.mixPubKey, NoDelay,
        ) # No delay for last hop

    publicKeys.add(mixPubKey)

    let multiAddrBytes = multiAddrToBytes(peerId, multiAddr).valueOr:
      mix_messages_error.inc(labelValues = ["Entry/SURB", "INVALID_MIX_INFO"])
      return err("failed to convert multiaddress to bytes: " & error)

    hops.add(Hop.init(multiAddrBytes))

    delays.add(hopDelay)

  return createSURB(publicKeys, delays, hops, id, mixProto.rng)

proc buildSurbs(
    mixProto: MixProtocol,
    incoming: AsyncQueue[seq[byte]],
    numSurbs: uint8,
    destPeerId: PeerId,
    exitPeerId: PeerId,
): Result[tuple[surbs: seq[SURB], session: Opt[SurbSession]], string] =
  if numSurbs == 0:
    # Fire-and-forget send: no reply expected, so nothing to register.
    return ok((@[], Opt.none(SurbSession)))

  var response: seq[SURB]
  let session = mixProto.surbStore.newSession()

  for _ in 0.uint8 ..< numSurbs:
    # Uniqueness rests on 128 bits of CSPRNG output, per spec Section 8.7.2
    # Step 2. No collision check: a repeat would mean the RNG has failed, which
    # compromises the SURB reply keys themselves, not just this index.
    var id: SURBIdentifier
    mixProto.rng.generate(id)

    let surb = mixProto.buildSurb(id, destPeerId, exitPeerId).valueOr:
      # Release whatever this group already registered; a partially built
      # group can never receive a usable reply.
      session.release()
      return err(error)

    mixProto.surbStore.add(
      id,
      ConnCreds(
        igroup: session.igroup,
        incoming: incoming,
        surbSecret: surb.secret.get(),
        surbKey: surb.key,
      ),
    ).isOkOr:
      session.release()
      return err(error)

    response.add(surb)

  return ok((response, Opt.some(session)))

proc prepareMsgWithSurbs(
    mixProto: MixProtocol,
    incoming: AsyncQueue[seq[byte]],
    msg: sink seq[byte],
    numSurbs: uint8 = 0,
    destPeerId: PeerId,
    exitPeerId: PeerId,
): Result[tuple[msg: seq[byte], session: Opt[SurbSession]], string] =
  let built = mixProto.buildSurbs(incoming, numSurbs, destPeerId, exitPeerId).valueOr:
    return err(error)
  let serialized = serializeMessageWithSURBs(msg, built.surbs).valueOr:
    built.session.get(nil).release()
    return err(error)
  ok((serialized, built.session))

type SendPacketLogType* = enum
  Entry
  Reply

type SendPacketLogConfig = object
  logType: SendPacketLogType
  when defined(enable_mix_benchmarks):
    startTime: Time
    metadata: Metadata

type SendPacketError = object
  msg: string
  neverWritten: bool
    ## True only when no byte of the packet can have left this node, which is
    ## the one case where its slot may be refunded and its proof reused.

proc sendPacket(
    mixProto: MixProtocol,
    peerId: PeerId,
    multiAddress: MultiAddress,
    sphinxPacket: SphinxPacket,
    logConfig: SendPacketLogConfig,
): Future[Result[void, SendPacketError]] {.async: (raises: [CancelledError]).} =
  ## Send the wrapped message to the first mix node in the selected path.
  ## Applies the sender pre-send delay (mix.md §8.5.2 step 3.f) before the
  ## first-hop write to break burst timing correlation.

  let label = $logConfig.logType
  let serialized = sphinxPacket.serialize()

  # §8.5.2 step 3.f: hold before first-hop transmit (entry and SURB replies).
  # Overlap proof generation with the hold, same as the intermediate path, so
  # spam-proof work does not stack on top of the sampled delay.
  let initialDelay = mixProto.delayStrategy.generateForSender()
  let proofGenStartTime = Moment.now()
  let delayFut = sleepAsync(initialDelay.toDuration)

  # proofGenTimeMs is captured at proof completion, inside the closure, so it
  # measures proof cost alone — not max(proof, delay) as after allFutures.
  var proofGenTimeMs: int64
  let proofGenFut = (
    proc(): Future[Result[tuple[packet: seq[byte], proofToken: seq[byte]], string]] {.
        async: (raises: [CancelledError])
    .} =
      let res = await mixProto.generateAndAppendProof(serialized, label)
      proofGenTimeMs = (Moment.now() - proofGenStartTime).milliseconds
      return res
  )()

  defer:
    await cancelAndWait(proofGenFut, delayFut)
  await allFutures(proofGenFut, delayFut)

  mixProto.spamProtection.withValue(sp):
    if proofGenTimeMs > initialDelay.int64:
      warn "Proof generation time exceeds sampled sender delay",
        proofGenTimeMs,
        sampledDelay = initialDelay,
        hint = "Increase the minimum delay floor or reduce proof generation time"

  let (packetToSend, proofToken) = (await proofGenFut).valueOr:
    return err(SendPacketError(msg: error, neverWritten: true))

  when defined(enable_mix_benchmarks):
    if logConfig.logType == Entry:
      benchmarkLog "Sender",
        mixProto.switch.peerInfo.peerId,
        logConfig.startTime,
        logConfig.metadata,
        Opt.none(PeerId),
        Opt.some(peerId)

  # The SURB gives the first hop of a reply.
  # This node did not select it.
  let ownFirstHop = logConfig.logType == Entry

  # Only a failed first dial proves the packet never left this node, so its
  # messageId can be reused. After any write attempt the next hop may hold the
  # proof: reissuing the messageId in this epoch would be an RLN double-signal,
  # so the proof stays spent, including when a retry's redial fails.
  let conn =
    try:
      await mixProto.getConn(peerId, @[multiAddress], @[MixProtocolID])
    except DialFailedError as exc:
      # A dial that the stop ended is not a failure of the hop.
      if mixProto.started:
        mix_messages_error.inc(labelValues = [label, "SEND_FAILED"])
        if ownFirstHop:
          mixProto.backOffHop(peerId, exc)
      if proofToken.len > 0:
        mixProto.spamProtection.withValue(sp):
          sp.reclaimProofToken(proofToken)
      return err(
        SendPacketError(
          msg: fmt"Failed to dial to next hop ({peerId}, {multiAddress}): {exc.msg}",
          neverWritten: true,
        )
      )

  try:
    when defined(enable_mix_benchmarks):
      await mixProto.writeLpWithRetry(
        conn, peerId, @[multiAddress], @[MixProtocolID], logConfig.metadata.serialize()
      )
    await mixProto.writeLpWithRetry(
      conn, peerId, @[multiAddress], @[MixProtocolID], packetToSend
    )
  except DialFailedError as exc:
    # A dial that the stop ended is not a failure of the hop.
    if mixProto.started:
      mix_messages_error.inc(labelValues = [label, "SEND_FAILED"])
      if ownFirstHop:
        mixProto.backOffHop(peerId, exc)
    return err(
      SendPacketError(
        msg: fmt"Failed to redial next hop ({peerId}, {multiAddress}): {exc.msg}"
      )
    )
  except LPStreamError as exc:
    mix_messages_error.inc(labelValues = [label, "SEND_FAILED"])
    return err(
      SendPacketError(
        msg: fmt"Failed to write to next hop ({peerId}, {multiAddress}): {exc.msg}"
      )
    )
  except CancelledError as exc:
    raise exc

  mix_messages_forwarded.inc(labelValues = [label])
  return ok()

proc buildMessage(
    msg: sink seq[byte], codec: string
): Result[Message, (string, string)] =
  let
    mixMsg = MixMessage.init(move(msg), codec)
    serialized = mixMsg.serialize()

  let padded = addPadding(serialized).valueOr:
    return err(("message size exceeds maximum payload size", "INVALID_SIZE"))

  ok(padded)

type DestinationType* = enum
  ForwardAddr
  MixNode

## Represents the final target of a mixnet message.  
## contains the peer id and multiaddress of the destination node
## if the exit != destination  
type MixDestination* = object
  peerId: PeerId
  case kind: DestinationType
  of ForwardAddr:
    address: MultiAddress
  else:
    discard

proc `$`*(d: MixDestination): string =
  case d.kind
  of ForwardAddr:
    return "MixDestination[ForwardAddr](" & $d.address & "/p2p/" & $d.peerId & ")"
  of MixNode:
    return "MixDestination[MixNode](" & $d.peerId & ")"

when defined(libp2p_mix_experimental_exit_is_dest):
  proc exitNode*(T: typedesc[MixDestination], p: PeerId): T =
    T(kind: DestinationType.MixNode, peerId: p)

proc forwardToAddr*(T: typedesc[MixDestination], p: PeerId, address: MultiAddress): T =
  T(kind: DestinationType.ForwardAddr, peerId: p, address: address)

proc init*(T: typedesc[MixDestination], p: PeerId, address: MultiAddress): T =
  MixDestination.forwardToAddr(p, address)

proc anonymizeLocalProtocolSend*(
    mixProto: MixProtocol,
    incoming: AsyncQueue[seq[byte]],
    msg: sink seq[byte],
    codec: string,
    destination: MixDestination,
    numSurbs: uint8,
): Future[Result[Opt[SurbSession], string]] {.
    async: (raises: [CancelledError, LPStreamError])
.} =
  ## On success returns a handle to the reply credentials registered for this
  ## send (or `Opt.none` when `numSurbs == 0`), so the caller can release them
  ## promptly when its connection closes.
  when not defined(libp2p_mix_experimental_exit_is_dest):
    doAssert destination.kind == ForwardAddr, "Only exit != destination is allowed"

  mix_messages_recvd.inc(labelValues = ["Entry"])
  let capacity = getMaxMessageSizeForCodec(codec, numSurbs).valueOr:
    mix_messages_error.inc(labelValues = ["Entry", "INVALID_SIZE"])
    return err("failure when calling getMaxMessageSizeForCodec: " & error)
  if msg.len > capacity:
    mix_messages_error.inc(labelValues = ["Entry", "INVALID_SIZE"])
    return err(
      "message exceeds the codec and reply payload capacity, size: " & $msg.len &
        ", capacity: " & $capacity
    )

  # Note: the cover-traffic slot is claimed further down, immediately before
  # the packet is sent, so validation failures below never consume one.

  var logConfig = SendPacketLogConfig(logType: Entry)
  when defined(enable_mix_benchmarks):
    # Assumes a fixed message layout whose first 16 bytes are the time at
    # origin and msgId
    logConfig.startTime = getTime()
    logConfig.metadata = Metadata.deserialize(msg)

  var
    publicKeys: seq[FieldElement] = @[]
    hop: seq[Hop] = @[]
    delays: seq[Delay] = @[]
    exitPeerId: PeerId

  let numMixNodes = mixProto.nodePool.len
  var numAvailableNodes = numMixNodes

  # The destination is usable when the pool has a hop address for it. A usable
  # destination is not a hop on the way to itself, so one node less is available.
  let destinationUsable = mixProto.nodePool.get(destination.peerId).isSome()
  if destinationUsable:
    numAvailableNodes = numMixNodes - 1

  if numAvailableNodes < PathLength:
    mix_messages_error.inc(labelValues = ["Entry", "LOW_MIX_POOL"])
    return err(
      fmt"No. of public mix nodes ({numAvailableNodes}) less than path length ({PathLength})."
    )

  var poolPeerIds = mixProto.nodePool.peerIds()
  var availableIndices = toSeq(0 ..< poolPeerIds.len)

  let index = poolPeerIds.find(destination.peerId)
  if index != -1:
    availableIndices.del(index)
  if destination.kind == MixNode and not destinationUsable:
    return err("Destination is not a mix node with a usable address")

  var nextHopAddr: MultiAddress
  var nextHopPeerId: PeerId
  # The backed off peers that the draw of the first hop skipped.
  var skipped: seq[int]
  while hop.len < PathLength:
    if availableIndices.len == 0:
      mix_messages_error.inc(labelValues = ["Entry", "LOW_MIX_POOL"])
      return err("Ran out of available mix nodes while constructing path")

    let randomIndexPosition = cryptoRandomInt(mixProto.rng, availableIndices.len).valueOr:
      mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
      return err(fmt"Failed to generate random number: {error}")
    let selectedIndex = availableIndices[randomIndexPosition]
    var randPeerId = poolPeerIds[selectedIndex]
    availableIndices.del(randomIndexPosition)

    if hop.len == 0 and mixProto.hopIsBackedOff(randPeerId):
      skipped.add(selectedIndex)
      continue

    if destination.kind == ForwardAddr and randPeerId == destination.peerId:
      continue

    if hop.len == PathLength - 1:
      case destination.kind
      of ForwardAddr:
        exitPeerId = randPeerId
      of MixNode:
        exitPeerId = destination.peerId
        randPeerId = destination.peerId

    debug "Selected mix node: ", indexInPath = hop.len

    let mixPubInfo = mixProto.nodePool.get(randPeerId).valueOr:
      # This is not an error. The peer has no address that a path can use now,
      # and a later record can give it one. So it stays in the pool, and the
      # draw continues with no error count.
      trace "Skipping a pool member with no usable address", peerId = randPeerId
      continue
    let (peerId, multiAddr, mixPubKey, _) = mixPubInfo.get()

    let multiAddrBytes = multiAddrToBytes(peerId, multiAddr).valueOr:
      # See above. The peer stays in the pool, and the draw continues. The pool
      # returns only an address that the header can carry, so this is a guard.
      trace "Failed to convert multiaddress to bytes, skipping node",
        error = error, peerId = peerId, multiAddr = multiAddr
      continue

    publicKeys.add(mixPubKey)

    if hop.len == 0:
      nextHopAddr = multiAddr
      nextHopPeerId = peerId
      # The later hops draw from the whole pool.
      availableIndices.add(skipped)

    delays.add(
      if hop.len != PathLength - 1:
        mixProto.delayStrategy.generateForEntry()
      else:
        NoDelay
    )
    hop.add(Hop.init(multiAddrBytes))

  # Encode destination
  let destHop =
    if destination.kind == ForwardAddr:
      let destAddrBytes = multiAddrToBytes(destination.peerId, destination.address).valueOr:
        mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
        return err(fmt"Failed to convert multiaddress to bytes: {error}")
      Hop.init(destAddrBytes)
    else:
      Hop()

  var prepared = mixProto.prepareMsgWithSurbs(
    incoming, move(msg), numSurbs, destination.peerId, exitPeerId
  ).valueOr:
    return err(fmt"Could not prepend SURBs: {error}")

  let session = prepared.session

  # Past this point the reply credentials are registered, so every failure
  # must release them: the packet never left this process, so no reply can
  # ever arrive to clean them up.
  template releaseAndFail(msg: string): auto =
    session.get(nil).release()
    return err(msg)

  let message = buildMessage(move(prepared.msg), codec).valueOr:
    mix_messages_error.inc(labelValues = ["Entry", error[1]])
    releaseAndFail(fmt"Error building message: {error[0]}")

  # Wrap in Sphinx packet
  let sphinxPacket = wrapInSphinxPacket(message, publicKeys, delays, hop, destHop).valueOr:
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    releaseAndFail(fmt"Failed to wrap in sphinx packet: {error}")

  # Claim a slot for local origination (Mix Cover Traffic spec §6.3).
  # Claimed here rather than on entry so that validation failures above never
  # consume a slot.
  var claimEpoch: uint64
  mixProto.coverTraffic.withValue(ct):
    let claim = ct.slotPool.claimSlot()
    if not claim.success:
      mix_slot_claim_rejected.inc(labelValues = ["send"])
      releaseAndFail("No slots available in current epoch")
    claimEpoch = ct.slotPool.epoch
    # Reclaim proof token from discarded cover packet for messageId reuse
    if claim.reclaimedToken.len > 0:
      mixProto.spamProtection.withValue(sp):
        sp.reclaimProofToken(claim.reclaimedToken)

  # Send the wrapped message to the first mix node in the selected path
  (await mixProto.sendPacket(nextHopPeerId, nextHopAddr, sphinxPacket, logConfig)).isOkOr:
    # A packet that may have reached the next hop keeps its slot, matching its
    # proof, which sendPacket only reclaims when nothing was written.
    if error.neverWritten:
      mixProto.coverTraffic.withValue(ct):
        ct.slotPool.unclaimSlot(claimEpoch)
    releaseAndFail(error.msg)

  return ok(session)

proc sendSurbReply*(
    mixProto: MixProtocol, surb: SURB, msg: sink seq[byte]
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  let (peerId, multiAddr) = surb.hop.get().bytesToMultiAddr().valueOr:
      return err("could not obtain multiaddress from hop: " & error)

  # Reply messages don't require an application codec: routing is determined by the SURB.
  let message = buildMessage(move(msg), "").valueOr:
    return err("could not build reply message: " & error[0])

  let sphinxPacket = useSURB(surb, message)

  var claimEpoch: uint64
  mixProto.coverTraffic.withValue(ct):
    let claim = ct.slotPool.claimSlot()
    if not claim.success:
      mix_slot_claim_rejected.inc(labelValues = ["reply"])
      return err("No slots available in current epoch")
    claimEpoch = ct.slotPool.epoch
    if claim.reclaimedToken.len > 0:
      mixProto.spamProtection.withValue(sp):
        sp.reclaimProofToken(claim.reclaimedToken)

  (
    await mixProto.sendPacket(
      peerId, multiAddr, sphinxPacket, SendPacketLogConfig(logType: Reply)
    )
  ).isOkOr:
    # A packet that may have reached the next hop keeps its slot, matching its
    # proof, which sendPacket only reclaims when nothing was written.
    if error.neverWritten:
      mixProto.coverTraffic.withValue(ct):
        ct.slotPool.unclaimSlot(claimEpoch)
    return err("could not send reply: " & error.msg)
  return ok()

type PathNode = object
  peerId: PeerId
  multiAddr: MultiAddress
  mixPubKey: FieldElement

proc selectRandomNodes(
    mixProto: MixProtocol, count: int, excludePeerIds: HashSet[PeerId]
): Result[seq[PathNode], string] {.raises: [].} =
  var available = mixProto.nodePool.peerIds().filterIt(it notin excludePeerIds)
  if available.len < count:
    return err(
      "Not enough mix nodes in pool (available=" & $available.len & ", needed=" & $count &
        ")"
    )

  var firstCandidates = available.filterIt(not mixProto.hopIsBackedOff(it))
  if firstCandidates.len == 0:
    return err("Every first hop candidate is backed off")
  let first = ?mixProto.drawUsable(firstCandidates)
  available.keepItIf(it != first.peerId)

  # Only the first hop skips a backed off peer.
  var mixPubInfos = @[first]
  while mixPubInfos.len < count:
    mixPubInfos.add(?mixProto.drawUsable(available))

  var selected: seq[PathNode]
  for mixPubInfo in mixPubInfos:
    selected.add(
      PathNode(
        peerId: mixPubInfo.peerId,
        multiAddr: mixPubInfo.multiAddr,
        mixPubKey: mixPubInfo.mixPubKey,
      )
    )
  ok(selected)

proc buildCoverPacket*(
    mixProto: MixProtocol, epoch: uint64
): Future[Result[CoverPacketBuild, string]] {.async: (raises: [CancelledError]).} =
  ## Build a cover Sphinx packet with a loop path (self = exit node),
  ## random payload .
  let nodes = mixProto.selectRandomNodes(
    PathLength - 1, [mixProto.mixNodeInfo.peerId].toHashSet
  ).valueOr:
    return err(error)

  var
    publicKeys: seq[FieldElement] = @[]
    hops: seq[Hop] = @[]
    delays: seq[Delay] = @[]

  for node in nodes:
    let addrBytes = multiAddrToBytes(node.peerId, node.multiAddr).valueOr:
      return err("Failed to convert multiaddress to bytes: " & error)
    publicKeys.add(node.mixPubKey)
    hops.add(Hop.init(addrBytes))
    delays.add(mixProto.delayStrategy.generateForEntry())

  let selfAddrBytes = multiAddrToBytes(
    mixProto.mixNodeInfo.peerId, mixProto.mixNodeInfo.multiAddr
  ).valueOr:
    return err("Failed to convert self multiaddress to bytes: " & error)
  publicKeys.add(mixProto.mixNodeInfo.mixPubKey)
  hops.add(Hop.init(selfAddrBytes))
  delays.add(NoDelay)

  # Identify cover packets at exit processing
  let maxMsgSize = getMaxMessageSizeForCodec(CoverTrafficCodec).valueOr:
    return err("Failed to get max message size for cover codec: " & error)
  var randomPayload = newSeq[byte](maxMsgSize)
  mixProto.rng.generate(randomPayload)

  let message = buildMessage(move(randomPayload), CoverTrafficCodec).valueOr:
    return err("Error building cover message: " & error[0])

  let sphinxPacket = wrapInSphinxPacket(message, publicKeys, delays, hops, Hop()).valueOr:
    return err("Failed to wrap cover sphinx packet: " & error)

  let serialized = sphinxPacket.serialize()
  let (packetToSend, proofToken) =
    if mixProto.spamProtection.isSome() and
        not mixProto.spamProtection.get().precomputeCoverProofs():
      (serialized, newSeq[byte]())
    else:
      (await mixProto.generateAndAppendProof(serialized, "Cover", Opt.some(epoch))).valueOr:
        return err("Failed to generate proof for cover packet: " & error)

  let firstNode = nodes[0]
  return ok(
    CoverPacketBuild(
      packet: packetToSend,
      firstHopPeerId: firstNode.peerId,
      firstHopAddr: firstNode.multiAddr,
      proofToken: proofToken,
    )
  )

proc buildCoverPacket*(
    mixProto: MixProtocol
): Future[Result[CoverPacketBuild, string]] {.async: (raises: [CancelledError]).} =
  var epoch: uint64
  mixProto.coverTraffic.withValue(ct):
    epoch = ct.slotPool.epoch
  return await mixProto.buildCoverPacket(epoch)

proc generateAndAppendCoverProof(
    mixProto: MixProtocol, packet: seq[byte], epoch: Opt[uint64]
): Future[Result[seq[byte], string]] {.async: (raises: [CancelledError]).} =
  if mixProto.spamProtection.isSome() and
      not mixProto.spamProtection.get().precomputeCoverProofs():
    let proved = await mixProto.generateAndAppendProof(packet, "Cover", epoch)
    return proved.map(
      proc(value: auto): seq[byte] =
        value.packet
    )
  return ok(packet)

proc writeCoverPacket(
    mixProto: MixProtocol, peerId: PeerId, multiAddr: MultiAddress, packet: seq[byte]
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  try:
    await mixProto.writeLp(peerId, @[multiAddr], @[MixProtocolID], packet)
    mix_messages_forwarded.inc(labelValues = ["Cover"])
    return ok()
  except DialFailedError as exc:
    # A dial that the stop ended is not a failure of the hop.
    if mixProto.started:
      mix_messages_error.inc(labelValues = ["Cover", "SEND_FAILED"])
      mixProto.backOffHop(peerId, exc)
    return err("Failed to dial for cover packet: " & exc.msg)
  except LPStreamError as exc:
    mix_messages_error.inc(labelValues = ["Cover", "SEND_FAILED"])
    return err("Failed to write cover packet: " & exc.msg)

proc sendCoverPacket*(
    mixProto: MixProtocol,
    peerId: PeerId,
    multiAddr: MultiAddress,
    packet: seq[byte],
    epoch: Opt[uint64] = Opt.none(uint64),
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  let proved = (await mixProto.generateAndAppendCoverProof(packet, epoch)).valueOr:
    return err(error)
  return await mixProto.writeCoverPacket(peerId, multiAddr, proved)

method start*(mixProto: MixProtocol) {.async: (raises: [CancelledError]).} =
  await procCall LPProtocol(mixProto).start()
  mixProto.coverTraffic.withValue(ct):
    await ct.start()

method stop*(mixProto: MixProtocol) {.async: (raises: []).} =
  ## Stop the MixProtocol background tasks, cancel the in-flight
  ## handleMixMessages futures and the hop dials, and close a stream whose dial
  ## completes after the stop began.
  mixProto.coverTraffic.withValue(ct):
    await ct.stop()
  mixProto.started = false
  # An entry of `dialing` is the future of a dial and the addresses of that dial.
  # The mapIt takes the futures, and the stop cancels them below.
  let dials = toSeq(mixProto.dialing.values).mapIt(it.dial)

  # Cancelling fires the completion callback, which deletes from this table.
  let pending = toSeq(mixProto.ongoingMixMessages.values)
  mixProto.ongoingMixMessages.clear()
  if pending.len > 0:
    await noCancel allFutures(pending.mapIt(it.cancelAndWait()))

  await mixProto.tagManager.stop()

  await mixProto.surbStore.stop()
  mixProto.surbStore.clear()

  if dials.len > 0:
    await noCancel allFutures(dials.mapIt(it.cancelAndWait()))
  for dial in dials:
    if dial.completed():
      await dial.value.close()

proc init*(
    mixProto: MixProtocol,
    mixNodeInfo: MixNodeInfo,
    switch: Switch,
    tagManager: TagManager = TagManager.new(),
    spamProtection: Opt[SpamProtection] = default(Opt[SpamProtection]),
    delayStrategy: Opt[DelayStrategy] = Opt.none(DelayStrategy),
    coverTraffic: Opt[CoverTraffic] = Opt.none(CoverTraffic),
    surbStore: SurbStore = nil,
    hopBackoff: Duration = DefaultHopBackoff,
    hopAddressClasses: set[MixAddressClass] = AllMixAddressClasses,
) {.raises: [].} =
  ## Initialize a MixProtocol instance.
  ##
  ## A nil `surbStore` gets a default one. Defaulting to nil rather than
  ## `SurbStore.new()` keeps the constructor out of the parameter list, so
  ## callers do not need `surb_store`'s `new` in scope.
  ##
  ## Mix node public keys should be populated via the nodePool after
  ## initialization using `mixProto.nodePool.add(mixPubInfo)`.
  ##
  ## `hopAddressClasses` are the address classes that the hop address of a
  ## pool member can have. A pool member with no address of these classes is
  ## on no path that this node builds. The default accepts each class.
  ##
  ## The classes do not apply to the address of this node or to a destination
  ## address, because the library does not select these addresses. The host
  ## gives the address of this node in `mixNodeInfo` or with
  ## `setLocalMultiAddr`. The caller of a send gives the destination address.
  ## In each case the library has one address and no other address to use in
  ## its place. So the host makes sure that other nodes can dial the address
  ## of this node. If they cannot, no reply and no cover packet comes back to
  ## this node. A destination that is a mix node has no address from the
  ## caller. It is a pool member, so the classes apply to it.
  ##
  ## The classes also do not apply to an address that this node reads from
  ## the header of a packet that it forwards. The sender of that packet built
  ## the path.
  ##
  ## Default delay strategy is `ExponentialDelayStrategy` (mean 100 ms for both
  ## per-hop encoding and the sender pre-send hold). When `spamProtection` is
  ## enabled the default is `SpamProtectionDelayStrategy` instead (same means,
  ## 100 ms delay floor) so proof generation time cannot dominate short sampled
  ## delays and set the send time.
  ##
  ## A first hop that fails a dial is not the first hop for `hopBackoff`.

  doAssert not switch.rng.isNil, "Switch must have RNG initialized"
  doAssert hopAddressClasses != {}, "hopAddressClasses must have one class or more"

  let store =
    if surbStore.isNil:
      SurbStore.new()
    else:
      surbStore

  # A SURB reply is only accepted while its replay tag is still cached, so
  # holding credentials longer than the tag TTL cannot buy anything.
  doAssert store.ttl <= tagManager.tagTTL,
    "SURB credential TTL must not exceed the replay tag TTL"

  mixProto.mixNodeInfo = mixNodeInfo
  mixProto.hopBackoff = hopBackoff
  mixProto.switch = switch
  mixProto.rng = switch.rng
  mixProto.nodePool = MixNodePool.new(switch.peerStore, hopAddressClasses)
  mixProto.tagManager = tagManager
  mixProto.surbStore = store
  mixProto.destReadBehaviors = newTable[string, DestReadBehavior]()

  mixProto.spamProtection = spamProtection
  mixProto.delayStrategy = delayStrategy.valueOr:
    if spamProtection.isSome:
      DelayStrategy(SpamProtectionDelayStrategy.new(rng = switch.rng))
    else:
      DelayStrategy(ExponentialDelayStrategy.new(rng = switch.rng))

  mixProto.coverTraffic = coverTraffic
  coverTraffic.withValue(ct):
    ct.setCoverPacketBuilder(
      proc(
          epoch: uint64
      ): Future[Result[CoverPacketBuild, string]] {.async: (raises: [CancelledError]).} =
        return await mixProto.buildCoverPacket(epoch)
    )
    ct.setCoverProofGenerator(
      proc(
          packet: seq[byte], epoch: uint64
      ): Future[Result[seq[byte], string]] {.async: (raises: [CancelledError]).} =
        return await mixProto.generateAndAppendCoverProof(packet, Opt.some(epoch))
    )
    ct.setCoverPacketSender(
      proc(
          peerId: PeerId, multiAddr: MultiAddress, packet: seq[byte], _: uint64
      ): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
        return await mixProto.writeCoverPacket(peerId, multiAddr, packet)
    )
    ct.setSendDelaySampler(
      proc(): Delay {.gcsafe, raises: [].} =
        mixProto.delayStrategy.generateForSender()
    )
    # Note: useInternalEpochTimer must be set to false when SpamProtection is
    # present, as SpamProtection provides epoch change notifications via
    # notifyEpochChange. Having both active would cause double epoch advances.
    spamProtection.withValue(sp):
      sp.registerOnEpochChange(
        proc(epoch: uint64) {.gcsafe, raises: [].} =
          ct.onEpochChange(epoch)
      )
      ct.setProofTokenValidator(
        proc(token: seq[byte]): bool {.gcsafe, raises: [].} =
          sp.isProofTokenValid(token)
      )
      ct.setProofTokenReclaimer(
        proc(token: seq[byte]) {.gcsafe, raises: [].} =
          sp.reclaimProofToken(token)
      )

  let onReplyDialer = proc(
      surb: SURB, message: seq[byte]
  ) {.async: (raises: [CancelledError]).} =
    # `message` is passed by value (the closure signature is fixed by
    # `ExitLayer.init`'s callback type). A full sink-through chain
    # would require updating the callback type in libp2p_mix.
    # For now: sendSurbReply() takes `sink seq[byte]` and `move()`s into
    # buildMessage internally — the optimization stops at this boundary.
    (await mixProto.sendSurbReply(surb, message)).isOkOr:
      error "could not send reply", err = error

  mixProto.exitLayer = ExitLayer.init(switch, onReplyDialer, mixProto.destReadBehaviors)

  mixProto.codecs = @[MixProtocolID]
  mixProto.handler = proc(
      conn: Connection, proto: string
  ) {.async: (raises: [CancelledError]).} =
    try:
      await mixProto.handleMixNodeConnection(conn)
    except LPStreamError as e:
      debug "Stream error", conn = conn, err = e.msg

proc new*(
    T: typedesc[MixProtocol],
    mixNodeInfo: MixNodeInfo,
    switch: Switch,
    tagManager: TagManager = TagManager.new(),
    spamProtection: Opt[SpamProtection] = default(Opt[SpamProtection]),
    delayStrategy: Opt[DelayStrategy] = Opt.none(DelayStrategy),
    coverTraffic: Opt[CoverTraffic] = Opt.none(CoverTraffic),
    surbStore: SurbStore = nil,
    hopBackoff: Duration = DefaultHopBackoff,
    hopAddressClasses: set[MixAddressClass] = AllMixAddressClasses,
): T {.raises: [].} =
  ## Create a new MixProtocol instance.
  ##
  ## Mix node public keys should be populated via the nodePool after
  ## creation using `mixProto.nodePool.add(mixPubInfo)`.
  ##
  ## When `spamProtection` is enabled, callers should prefer
  ## `SpamProtectionDelayStrategy` to avoid timing correlation between proof
  ## generation and short exponential delays.
  let mixProto = new(T)
  mixProto.init(
    mixNodeInfo, switch, tagManager, spamProtection, delayStrategy, coverTraffic,
    surbStore, hopBackoff, hopAddressClasses,
  )
  mixProto
