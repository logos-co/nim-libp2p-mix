# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronicles, chronos, sequtils, results, sets
import std/[strformat, tables], metrics
import
  ./[
    curve25519, delay, padding, mix_message, mix_node, sphinx, serialization,
    tag_manager, mix_metrics, exit_layer, multiaddr, exit_connection, spam_protection,
    delay_strategy, mix_pool, pool, cover_traffic, surb_store,
  ]
import ./mix_events
import libp2p/protocols/protocol
import libp2p/stream/[connection, lpstream]
import libp2p/[switch, multicodec, peerinfo, varint]
import libp2p/crypto/crypto

export mix_pool
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

func isCoverTraffic*(msg: MixMessage): bool =
  ## Returns true if the message is a cover traffic packet.
  msg.codec == CoverTrafficCodec

type PeerStreamLock = ref object
  lock: AsyncLock
    ## Lets one caller of getConn look up and dial for this peer at a time, so
    ## concurrent sends to the peer reuse one cached stream.
  users: int ## Callers inside getConn. The last one deletes the entry from streamLocks.

## Mix Protocol defines a decentralized anonymous message routing layer for libp2p networks.
## It enables sender anonymity by routing each message through a decentralized mix overlay
## network composed of participating libp2p nodes, known as mix nodes. Each message is
## routed independently in a stateless manner, allowing other libp2p protocols to selectively
## anonymize messages without modifying their core protocol behavior.
type MixProtocol* = ref object of LPProtocol
  mixNodeInfo: MixNodeInfo
  switch*: Switch
  pool*: MixPool ## The peers this node routes through. See mix_pool.nim.
  brokerCtx: BrokerContext ## Where this node emits its events.
  tagManager: TagManager
  exitLayer: ExitLayer
  rng: Rng
  surbStore: SurbStore
    ## Reply credentials for SURBs this node has issued. Expires entries whose
    ## reply never arrives; see surb_store.nim.
  destReadBehaviors: TableRef[string, DestReadBehavior]
  connPool: Table[PeerId, Connection]
  streamLocks: Table[PeerId, PeerStreamLock]
  spamProtection: Opt[SpamProtection]
  delayStrategy: DelayStrategy
  coverTraffic*: Opt[CoverTraffic]
  ongoingMixMessages: seq[Future[void]]
    ## Tracks all in-flight handleMixMessages futures so they can be
    ## cancelled on stop and waited for during teardown.

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

proc removeClosedConnections(
    mixProto: MixProtocol, failed: Connection
) {.async: (raises: []).} =
  var stale: seq[tuple[peerId: PeerId, conn: Connection]]
  for peerId, conn in mixProto.connPool:
    if conn == failed or not mixProto.switch.isConnected(peerId):
      stale.add((peerId, conn))
  for (peerId, conn) in stale:
    # Another caller can replace the entry while this proc awaits a close.
    if mixProto.connPool.getOrDefault(peerId) == conn:
      mixProto.connPool.del(peerId)
    await conn.close()

proc getConn(
    mixProto: MixProtocol,
    pid: PeerId,
    addrs: seq[MultiAddress],
    codecs: seq[string],
    failed: Connection = nil,
): Future[Connection] {.async: (raises: [DialFailedError, CancelledError]).} =
  var streamLock = mixProto.streamLocks.getOrDefault(pid)
  if streamLock.isNil:
    streamLock = PeerStreamLock(lock: newAsyncLock())
    mixProto.streamLocks[pid] = streamLock
  streamLock.users.inc()
  try:
    await streamLock.lock.acquire()
    defer:
      try:
        streamLock.lock.release()
      except AsyncLockError as exc:
        raiseAssert "stream lock released without acquire: " & exc.msg
    if not failed.isNil:
      await mixProto.removeClosedConnections(failed)
    mixProto.connPool.withValue(pid, conn):
      return conn[]
    let c = await mixProto.switch.dial(pid, addrs, codecs)
    mixProto.connPool[pid] = c
    return c
  finally:
    streamLock.users.dec()
    if streamLock.users == 0 and mixProto.streamLocks.getOrDefault(pid) == streamLock:
      mixProto.streamLocks.del(pid)

proc writeLp(
    mixProto: MixProtocol,
    pid: PeerId,
    addrs: seq[MultiAddress],
    codecs: seq[string],
    payload: seq[byte],
) {.async: (raises: [DialFailedError, LPStreamError, CancelledError]).} =
  let c = await mixProto.getConn(pid, addrs, codecs)
  try:
    await c.writeLp(payload)
  except LPStreamClosedError, LPStreamResetError, LPStreamRemoteClosedError,
      LPStreamConnDownError:
    let replacement = await mixProto.getConn(pid, addrs, codecs, failed = c)
    await replacement.writeLp(payload)

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

    # The exit replies via every SURB in the group, so N replies race; the
    # first one to arrive invalidates the rest.
    mixProto.surbStore.release(connCred.igroup)

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
    mixProto.coverTraffic.withValue(ct):
      let claim = ct.slotPool.claimSlot()
      if not claim.success:
        warn "Slot exhaustion, dropping forwarded packet"
        mix_messages_error.inc(labelValues = ["Intermediate", "SLOT_EXHAUSTED"])
        mix_slot_claim_rejected.inc(labelValues = ["forward"])
        return
      # Reclaim proof token from discarded cover packet for messageId reuse
      if claim.reclaimedToken.len > 0:
        mixProto.spamProtection.withValue(sp):
          sp.reclaimProofToken(claim.reclaimedToken)

    let actualDelay = mixProto.delayStrategy.generateForIntermediate(processedSP.delay)
    trace "Computed delay", encodedDelay = processedSP.delay, actualDelay

    # Forward to next hop
    let nextHopBytes = processedSP.nextHop.get()

    let (nextPeerId, nextAddr) = bytesToMultiAddr(nextHopBytes).valueOr:
      trace "Failed to convert bytes to multiaddress", err = error
      mix_messages_error.inc(labelValues = ["Intermediate", "INVALID_DEST"])
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

    let (outgoingPacket, _) = (await proofGenFut).valueOr:
      error "Failed to generate spam protection proof for next hop", err = error
      return

    try:
      when defined(enable_mix_benchmarks):
        await mixProto.writeLp(nextPeerId, @[nextAddr], @[MixProtocolID], metadataBytes)
      await mixProto.writeLp(nextPeerId, @[nextAddr], @[MixProtocolID], outgoingPacket)
      mix_messages_forwarded.inc(labelValues = ["Intermediate"])
    except CancelledError as exc:
      raise exc
    except DialFailedError as exc:
      MixHopDialFailed.emit(mixProto.brokerCtx, MixHopDialFailed(peerId: nextPeerId))
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
  let fut = runMixMessage(mixProto, fromPeerId, receivedBytes, metadataBytes)
  mixProto.ongoingMixMessages.add(fut)
  fut.addCallback(
    proc(_: pointer) {.gcsafe, raises: [].} =
      mixProto.ongoingMixMessages.keepItIf(not it.finished)
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
  let serializedMsg = MixMessage.init(@[], codec).serialize()
  let totalLen = serializedMsg.len + SurbLenSize + (int(numberOfSurbs) * SurbSize)
  if totalLen > DataSize:
    return err("cannot encode messages for this codec")
  return ok(DataSize - totalLen)

func poolErrorLabel(error: string): string =
  ## The metric label of a failed path selection.
  if error == NotEnoughMixNodes: "LOW_MIX_POOL" else: "POOL_UNAVAILABLE"

proc selectRandomNodes(
    mixProto: MixProtocol, count: int, exclude: openArray[PeerId]
): Result[seq[MixPubInfo], string] =
  mixProto.pool.selectRandomNodes(count, @[mixProto.mixNodeInfo.peerId] & @exclude)

proc selectReplyPeer*(
    mixProto: MixProtocol, excluded: seq[PeerId]
): Future[Result[PeerId, string]] {.async: (raises: [CancelledError]).} =
  ## Ask the pool for the final peer of a reply path.
  await mixProto.pool.selectReplyPeer(excluded)

method buildSurb*(
    mixProto: MixProtocol,
    id: SURBIdentifier,
    destPeerId: PeerId,
    exitPeerId: PeerId,
    finalPeer: Opt[PeerId] = Opt.none(PeerId),
): Result[SURB, string] {.base, gcsafe, raises: [].} =
  ## Select the final peer at random when the caller supplies none.
  ## `buildSurbs` passes the pool's choice from `selectReplyPeer`.
  let excluded = [mixProto.mixNodeInfo.peerId, destPeerId, exitPeerId]
  let finalPeerId = finalPeer.valueOr:
    let candidates = ?mixProto.selectRandomNodes(1, [destPeerId, exitPeerId])
    candidates[0].peerId
  if finalPeerId in excluded:
    return err("selected reply peer is excluded from this route")
  # Read the record again. The caller can await the pool's choice, and the
  # pool can drop the peer or change its keys or address in that time.
  let finalHop = (?mixProto.pool.usablePeer(finalPeerId)).valueOr:
    return err("selected reply peer is no longer usable")
  var selected = ?mixProto.selectRandomNodes(
    PathLength - 2, [destPeerId, exitPeerId, finalHop.peerId]
  )
  selected.add(finalHop)
  selected.add(mixProto.localMixPubInfo())
  var
    publicKeys: seq[FieldElement]
    hops: seq[Hop]
    delays: seq[Delay]
  for i, node in selected:
    let encoded = multiAddrToBytes(node.peerId, node.multiAddr).valueOr:
      mix_messages_error.inc(labelValues = ["Entry/SURB", "INVALID_MIX_INFO"])
      return err("failed to encode reply hop: " & error)
    debug "Selected mix node for surbs", indexInPath = i
    publicKeys.add(node.mixPubKey)
    hops.add(Hop.init(encoded))
    delays.add(
      if i == selected.high:
        NoDelay
      else:
        mixProto.delayStrategy.generateForEntry()
    )
  createSURB(publicKeys, delays, hops, id, mixProto.rng)

proc buildSurbs(
    mixProto: MixProtocol,
    incoming: AsyncQueue[seq[byte]],
    numSurbs: uint8,
    destPeerId, exitPeerId: PeerId,
): Future[Result[tuple[surbs: seq[SURB], session: Opt[SurbSession]], string]] {.
    async: (raises: [CancelledError])
.} =
  if numSurbs == 0:
    # Fire-and-forget send: no reply expected, so nothing to register.
    return ok((@[], Opt.none(SurbSession)))
  let excluded = @[mixProto.mixNodeInfo.peerId, destPeerId, exitPeerId]
  let usable = mixProto.pool.countUsable(excluded).valueOr:
    mix_messages_error.inc(labelValues = ["Entry/SURB", "POOL_UNAVAILABLE"])
    return err(error)
  if usable < PathLength - 1:
    mix_messages_error.inc(labelValues = ["Entry/SURB", "LOW_MIX_POOL"])
    return err("not enough usable mix nodes for a reply path")

  var response: seq[SURB]
  let session = mixProto.surbStore.newSession()
  var completed = false
  defer:
    if not completed:
      session.release()

  for _ in 0.uint8 ..< numSurbs:
    let finalPeer = (await mixProto.selectReplyPeer(excluded)).valueOr:
      mix_messages_error.inc(labelValues = ["Entry/SURB", poolErrorLabel(error)])
      return err(error)
    # Uniqueness rests on 128 bits of CSPRNG output, per spec Section 8.7.2
    # Step 2. No collision check: a repeat would mean the RNG has failed, which
    # compromises the SURB reply keys themselves, not just this index.
    var id: SURBIdentifier
    mixProto.rng.generate(id)
    let surb = mixProto.buildSurb(id, destPeerId, exitPeerId, Opt.some(finalPeer)).valueOr:
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
      return err(error)
    response.add(surb)

  completed = true
  return ok((response, Opt.some(session)))

type SendPacketLogType* = enum
  Entry
  Reply

type SendPacketLogConfig = object
  logType: SendPacketLogType
  when defined(enable_mix_benchmarks):
    startTime: Time
    metadata: Metadata

proc sendPacket(
    mixProto: MixProtocol,
    peerId: PeerId,
    multiAddress: MultiAddress,
    sphinxPacket: SphinxPacket,
    logConfig: SendPacketLogConfig,
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
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

  let (packetToSend, _) = (await proofGenFut).valueOr:
    return err(error)

  when defined(enable_mix_benchmarks):
    if logConfig.logType == Entry:
      benchmarkLog "Sender",
        mixProto.switch.peerInfo.peerId,
        logConfig.startTime,
        logConfig.metadata,
        Opt.none(PeerId),
        Opt.some(peerId)

  try:
    when defined(enable_mix_benchmarks):
      await mixProto.writeLp(
        peerId, @[multiAddress], @[MixProtocolID], logConfig.metadata.serialize()
      )
    await mixProto.writeLp(peerId, @[multiAddress], @[MixProtocolID], packetToSend)
  except DialFailedError as exc:
    MixHopDialFailed.emit(mixProto.brokerCtx, MixHopDialFailed(peerId: peerId))
    mix_messages_error.inc(labelValues = [label, "SEND_FAILED"])
    return err(fmt"Failed to dial to next hop ({peerId}, {multiAddress}): {exc.msg}")
  except LPStreamError as exc:
    mix_messages_error.inc(labelValues = [label, "SEND_FAILED"])
    return err(fmt"Failed to write to next hop ({peerId}, {multiAddress}): {exc.msg}")
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
    return err(error)
  if msg.len > capacity:
    mix_messages_error.inc(labelValues = ["Entry", "INVALID_SIZE"])
    return err("message exceeds the codec and reply payload capacity")

  # Note: the cover-traffic slot is claimed further down, immediately before
  # the packet is sent. Claiming here would consume a slot on every validation
  # failure below, and the pool has no refund path.

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

  var selected: seq[MixPubInfo]
  case destination.kind
  of ForwardAddr:
    selected = mixProto.selectRandomNodes(PathLength, [destination.peerId]).valueOr:
      mix_messages_error.inc(labelValues = ["Entry", poolErrorLabel(error)])
      return err(error)
    exitPeerId = selected[^1].peerId
  of MixNode:
    if destination.peerId == mixProto.mixNodeInfo.peerId:
      return err("Destination must be a remote mix node")
    let exit = (?mixProto.pool.usablePeer(destination.peerId)).valueOr:
      return err("Destination does not support mix")
    selected = mixProto.selectRandomNodes(PathLength - 1, [destination.peerId]).valueOr:
      mix_messages_error.inc(labelValues = ["Entry", poolErrorLabel(error)])
      return err(error)
    selected.add(exit)
    exitPeerId = exit.peerId

  let nextHopAddr = selected[0].multiAddr
  let nextHopPeerId = selected[0].peerId
  for i, node in selected:
    # usablePeer already checked that each selected address encodes.
    let encoded = multiAddrToBytes(node.peerId, node.multiAddr).valueOr:
      return err("failed to encode mix hop: " & error)
    debug "Selected mix node", indexInPath = i
    publicKeys.add(node.mixPubKey)
    hop.add(Hop.init(encoded))
    delays.add(
      if i == selected.high:
        NoDelay
      else:
        mixProto.delayStrategy.generateForEntry()
    )

  # Encode destination
  let destHop =
    if destination.kind == ForwardAddr:
      let destAddrBytes = multiAddrToBytes(destination.peerId, destination.address).valueOr:
        mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
        return err(fmt"Failed to convert multiaddress to bytes: {error}")
      Hop.init(destAddrBytes)
    else:
      Hop()

  let prepared = (
    await mixProto.buildSurbs(incoming, numSurbs, destination.peerId, exitPeerId)
  ).valueOr:
    return err(fmt"Could not build SURBs: {error}")
  let session = prepared.session

  # Past this point the reply credentials are registered. The caller gets the
  # handle to them only when the send completes, so every other exit releases
  # them here.
  var sent = false
  defer:
    if not sent:
      session.get(nil).release()

  var serialized = serializeMessageWithSURBs(msg, prepared.surbs).valueOr:
    return err(fmt"Could not prepend SURBs: {error}")
  let message = buildMessage(move(serialized), codec).valueOr:
    mix_messages_error.inc(labelValues = ["Entry", error[1]])
    return err(fmt"Error building message: {error[0]}")

  # Wrap in Sphinx packet
  let sphinxPacket = wrapInSphinxPacket(message, publicKeys, delays, hop, destHop).valueOr:
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return err(fmt"Failed to wrap in sphinx packet: {error}")

  # Claim a slot for local origination (Mix Cover Traffic spec §6.3).
  # Claimed here rather than on entry so that a slot is only consumed by a
  # packet that is actually emitted -- the pool has no refund path, so an
  # earlier claim would leak one on every validation failure above.
  mixProto.coverTraffic.withValue(ct):
    let claim = ct.slotPool.claimSlot()
    if not claim.success:
      mix_slot_claim_rejected.inc(labelValues = ["send"])
      return err("No slots available in current epoch")
    # Reclaim proof token from discarded cover packet for messageId reuse
    if claim.reclaimedToken.len > 0:
      mixProto.spamProtection.withValue(sp):
        sp.reclaimProofToken(claim.reclaimedToken)

  # Send the wrapped message to the first mix node in the selected path
  (await mixProto.sendPacket(nextHopPeerId, nextHopAddr, sphinxPacket, logConfig)).isOkOr:
    return err(error)

  sent = true
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

  mixProto.coverTraffic.withValue(ct):
    let claim = ct.slotPool.claimSlot()
    if not claim.success:
      mix_slot_claim_rejected.inc(labelValues = ["reply"])
      return err("No slots available in current epoch")
    if claim.reclaimedToken.len > 0:
      mixProto.spamProtection.withValue(sp):
        sp.reclaimProofToken(claim.reclaimedToken)

  (
    await mixProto.sendPacket(
      peerId, multiAddr, sphinxPacket, SendPacketLogConfig(logType: Reply)
    )
  ).isOkOr:
    return err("could not send reply: " & error)
  return ok()

proc buildCoverPacket*(
    mixProto: MixProtocol, epoch: uint64
): Future[Result[CoverPacketBuild, string]] {.async: (raises: [CancelledError]).} =
  ## Build a cover Sphinx packet with a loop path (self = exit node),
  ## random payload .
  let nodes = mixProto.selectRandomNodes(PathLength - 1, []).valueOr:
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
    MixHopDialFailed.emit(mixProto.brokerCtx, MixHopDialFailed(peerId: peerId))
    mix_messages_error.inc(labelValues = ["Cover", "SEND_FAILED"])
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
  ## Stop the MixProtocol background tasks and cancel all in-flight
  ## handleMixMessages futures.
  mixProto.started = false

  await mixProto.tagManager.stop()

  await mixProto.surbStore.stop()
  mixProto.surbStore.clear()

  mixProto.coverTraffic.withValue(ct):
    await ct.stop()

  # Snapshot the list and clear it before cancelling.
  let pending = mixProto.ongoingMixMessages
  mixProto.ongoingMixMessages = @[]
  if pending.len > 0:
    await noCancel allFutures(pending.mapIt(it.cancelAndWait()))

proc init*(
    mixProto: MixProtocol,
    mixNodeInfo: MixNodeInfo,
    switch: Switch,
    tagManager: TagManager = TagManager.new(),
    spamProtection: Opt[SpamProtection] = default(Opt[SpamProtection]),
    delayStrategy: Opt[DelayStrategy] = Opt.none(DelayStrategy),
    coverTraffic: Opt[CoverTraffic] = Opt.none(CoverTraffic),
    surbStore: SurbStore = nil,
    pool: MixPool = nil,
    brokerCtx: BrokerContext = DefaultBrokerContext,
) {.raises: [].} =
  ## Initialize a MixProtocol instance.
  ##
  ## A nil `surbStore` gets a default one. Defaulting to nil rather than
  ## `SurbStore.new()` keeps the constructor out of the parameter list, so
  ## callers do not need `surb_store`'s `new` in scope.
  ##
  ## `pool` supplies the peers to route through. A nil `pool` gets a
  ## `MixNodePool` on the switch's peer store. See mix_pool.nim.
  ##
  ## Default delay strategy is `ExponentialDelayStrategy` (mean 100 ms for both
  ## per-hop encoding and the sender pre-send hold). When `spamProtection` is
  ## enabled the default is `SpamProtectionDelayStrategy` instead (same means,
  ## 100 ms delay floor) so proof generation time cannot dominate short sampled
  ## delays and set the send time.

  doAssert not switch.rng.isNil, "Switch must have RNG initialized"

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
  mixProto.switch = switch
  mixProto.rng = switch.rng
  mixProto.pool =
    if pool.isNil:
      MixNodePool.new(switch.peerStore, switch.rng)
    else:
      pool
  mixProto.brokerCtx = brokerCtx
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
    pool: MixPool = nil,
    brokerCtx: BrokerContext = DefaultBrokerContext,
): T {.raises: [].} =
  ## Create a new MixProtocol instance.
  ##
  ## `pool` supplies the peers to route through. A nil `pool` gets a
  ## `MixNodePool` on the switch's peer store. See mix_pool.nim.
  ##
  ## When `spamProtection` is enabled, callers should prefer
  ## `SpamProtectionDelayStrategy` to avoid timing correlation between proof
  ## generation and short exponential delays.
  let mixProto = new(T)
  mixProto.init(
    mixNodeInfo, switch, tagManager, spamProtection, delayStrategy, coverTraffic,
    surbStore, pool,
  )
  mixProto.brokerCtx = brokerCtx
  mixProto
