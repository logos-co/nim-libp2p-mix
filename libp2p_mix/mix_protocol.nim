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

when defined(libp2p_mix_experimental_exit_is_dest):
  {.warning: "experimental support for mix exit == destination is enabled!".}

const MixProtocolID* = "/mix/1.0.0"

const CoverTrafficCodec* = "/mix/cover/1.0.0"
  ## Reserved codec for cover traffic packets. Cover packets use this codec
  ## so the exit node can identify and silently discard returning cover traffic.

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

proc cryptoRandomInt(rng: Rng, max: int): Result[int, string] =
  if max == 0:
    return err("Max cannot be zero.")
  let res = rng.generate(uint64) mod uint64(max)
  ok(res.int)

proc removeClosedConnections(
    mixProto: MixProtocol, pid: PeerId
) {.async: (raises: []).} =
  var peersToGC = mixProto.connPool
    .keys()
    .toSeq()
    .filterIt(not mixProto.switch.isConnected(it))
    .toHashSet()
  peersToGC.incl(pid)

  for p in peersToGC:
    var conn: Connection
    if mixProto.connPool.pop(p, conn):
      await conn.close()

proc getConn(
    mixProto: MixProtocol,
    pid: PeerId,
    addrs: seq[MultiAddress],
    codecs: seq[string],
    forceNewStream: bool = false,
): Future[Connection] {.async: (raises: [DialFailedError, CancelledError]).} =
  if forceNewStream:
    # GC all expired connections including the one used for `pid`
    await mixProto.removeClosedConnections(pid)
  try:
    return mixProto.connPool[pid]
  except KeyError:
    let c = await mixProto.switch.dial(pid, addrs, codecs)
    mixProto.connPool[pid] = c
    return c

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
    let c = await mixProto.getConn(pid, addrs, codecs, forceNewStream = true)
    await c.writeLp(payload)

proc generateAndAppendProof(
    mixProto: MixProtocol, packet: seq[byte], label: string
): Result[tuple[packet: seq[byte], proofToken: seq[byte]], string] =
  ## Generate spam protection proof and append it to the packet.
  ## Returns the packet with proof appended and an opaque proof token
  ## for proof slot tracking.
  let spamProtection = mixProto.spamProtection.valueOr:
    return ok((packet, newSeq[byte]()))

  let bindingData = packet
  let proofResult = spamProtection
    .generateProof(bindingData)
    .mapErr(
      proc(e: string): string =
        mix_messages_error.inc(labelValues = [label, "SPAM_PROOF_GEN_FAILED"])
        fmt"Failed to generate spam protection proof: {e}"
    ).valueOr:
      return err(error)

  let packetWithProof = appendProofToPacket(packet, proofResult.proof)
    .mapErr(
      proc(e: string): string =
        mix_messages_error.inc(labelValues = [label, "SPAM_PROOF_EMBED_FAILED"])
        fmt"Failed to append spam protection proof: {e}"
    ).valueOr:
      return err(error)

  ok((packetWithProof, proofResult.token))

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
): Result[void, string] =
  ## Verify a previously extracted spam protection proof.
  let spamProtection = mixProto.spamProtection.valueOr:
    return ok()

  let bindingData = sphinxPacket

  let verifyResult = spamProtection.verifyProof(proof, bindingData).valueOr:
    mix_messages_error.inc(labelValues = [label, "SPAM_PROOF_VERIFY_ERROR"])
    return err(fmt"Spam protection proof verification error: {error}")

  if not verifyResult:
    mix_messages_error.inc(labelValues = [label, "SPAM_PROOF_INVALID"])
    return err("Spam protection proof verification failed")

  trace "Spam protection proof verified successfully"
  ok()

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
  mixProto.verifyProof(sphinxBytes, spamProof, "Intermediate/Exit").isOkOr:
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
      peerId = mixProto.mixNodeInfo.peerId,
      message = deserialized.message,
      codec = deserialized.codec

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

    let proofGenFut = (
      proc(): Future[Result[tuple[packet: seq[byte], proofToken: seq[byte]], string]] {.
          async
      .} =
        return mixProto.generateAndAppendProof(
          processedSP.serializedSphinxPacket, "Intermediate"
        )
    )()

    await allFutures(proofGenFut, delayFut)

    mixProto.spamProtection.withValue(sp):
      let proofGenTimeMs = (Moment.now() - proofGenStartTime).milliseconds
      if proofGenTimeMs > actualDelay.int64:
        warn "Proof generation time exceeds sampled delay",
          proofGenTimeMs,
          sampledDelay = actualDelay,
          hint = "Increase the minimum delay floor or reduce proof generation time"

    let (outgoingPacket, _) = proofGenFut.value().valueOr:
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
      error "Failed to dial next hop: ", err = exc.msg
      mix_messages_error.inc(labelValues = ["Intermediate", "DIAL_FAILED"])
    except LPStreamError as exc:
      error "Failed to write to next hop: ", err = exc.msg
      mix_messages_error.inc(labelValues = ["Intermediate", "DIAL_FAILED"])
  of Duplicate:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "DUPLICATE"])
  of InvalidMAC:
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_MAC"])

proc proofSize(sp: Opt[SpamProtection]): int =
  ## Helper to get proof size from optional spam protection.
  ## Returns 0 if spam protection is None.
  if sp.isNone:
    return 0
  return sp.get().proofSize

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
  var availableIndices = toSeq(0 ..< poolPeerIds.len)

  # Select L mix nodes at random
  for i in 0 ..< PathLength:
    let (peerId, multiAddr, mixPubKey, hopDelay) =
      if i < PathLength - 1:
        let randomIndexPosition = cryptoRandomInt(mixProto.rng, availableIndices.len).valueOr:
          return err("failed to generate random num: " & error)
        let selectedIndex = availableIndices[randomIndexPosition]
        let randPeerId = poolPeerIds[selectedIndex]
        availableIndices.del(randomIndexPosition)
        debug "Selected mix node for surbs: ", indexInPath = i, peerId = randPeerId
        let mixPubInfo = mixProto.nodePool.get(randPeerId).valueOr:
          return err("could not get mix pub info for peer: " & $randPeerId)
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

proc sendPacket(
    mixProto: MixProtocol,
    peerId: PeerId,
    multiAddress: MultiAddress,
    sphinxPacket: SphinxPacket,
    logConfig: SendPacketLogConfig,
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  ## Send the wrapped message to the first mix node in the selected path

  let label = $logConfig.logType

  # Per-hop spam protection: Generate initial proof and append to packet
  let (packetToSend, _) = mixProto.generateAndAppendProof(
    sphinxPacket.serialize(), label
  ).valueOr:
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

  # Select L mix nodes at random
  let numMixNodes = mixProto.nodePool.len
  var numAvailableNodes = numMixNodes

  debug "Destination data", destination

  if mixProto.nodePool.get(destination.peerId).isSome:
    numAvailableNodes = numMixNodes - 1

  if numAvailableNodes < PathLength:
    mix_messages_error.inc(labelValues = ["Entry", "LOW_MIX_POOL"])
    return err(
      fmt"No. of public mix nodes ({numAvailableNodes}) less than path length ({PathLength})."
    )

  # Skip the destination peer
  var poolPeerIds = mixProto.nodePool.peerIds()
  var availableIndices = toSeq(0 ..< poolPeerIds.len)

  let index = poolPeerIds.find(destination.peerId)
  if index != -1:
    availableIndices.del(index)
  elif destination.kind == MixNode:
    return err("Destination does not support mix")

  var nextHopAddr: MultiAddress
  var nextHopPeerId: PeerId
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

    if destination.kind == ForwardAddr and randPeerId == destination.peerId:
      # Skip the destination peer
      continue

    # Last hop will be the exit node that will forward the request
    if hop.len == PathLength - 1:
      case destination.kind
      of ForwardAddr:
        # Last hop will be the exit node that will fwd the request
        exitPeerId = randPeerId
      of MixNode:
        # Exist node will be the destination
        exitPeerId = destination.peerId
        randPeerId = destination.peerId

    debug "Selected mix node: ", indexInPath = hop.len, peerId = randPeerId

    # Extract multiaddress, mix public key, and hop
    let mixPubInfoOpt = mixProto.nodePool.get(randPeerId)
    if mixPubInfoOpt.isNone:
      mix_messages_error.inc(labelValues = ["Entry", "INVALID_MIX_INFO"])
      trace "Failed to get mix pub info for peer, skipping and removing node from pool",
        peerId = randPeerId
      # Remove this node from the pool to prevent future selection
      discard mixProto.nodePool.remove(randPeerId)
      # Skip this node and try another
      continue
    let (peerId, multiAddr, mixPubKey, _) = mixPubInfoOpt.get().get()

    # Validate multiaddr before committing this node to the path
    let multiAddrBytes = multiAddrToBytes(peerId, multiAddr).valueOr:
      mix_messages_error.inc(labelValues = ["Entry", "INVALID_MIX_INFO"])
      trace "Failed to convert multiaddress to bytes, skipping and removing node from pool",
        error = error, peerId = peerId, multiAddr = multiAddr
      # Remove this node from the pool to prevent future selection
      discard mixProto.nodePool.remove(randPeerId)
      # Skip this node with invalid multiaddr and try another
      # in future lookup in peerStore to see if there is any other valid multiaddr for this peer and use that.
      continue

    # Only add to path after validation succeeds
    publicKeys.add(mixPubKey)

    if hop.len == 0:
      nextHopAddr = multiAddr
      nextHopPeerId = peerId

    let hopDelay =
      if hop.len != PathLength - 1:
        mixProto.delayStrategy.generateForEntry()
      else:
        NoDelay # No delay for exit node

    delays.add(hopDelay)

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
  # Claimed here rather than on entry so that a slot is only consumed by a
  # packet that is actually emitted -- the pool has no refund path, so an
  # earlier claim would leak one on every validation failure above.
  mixProto.coverTraffic.withValue(ct):
    let claim = ct.slotPool.claimSlot()
    if not claim.success:
      mix_slot_claim_rejected.inc(labelValues = ["send"])
      releaseAndFail("No slots available in current epoch")
    # Reclaim proof token from discarded cover packet for messageId reuse
    if claim.reclaimedToken.len > 0:
      mixProto.spamProtection.withValue(sp):
        sp.reclaimProofToken(claim.reclaimedToken)

  # Send the wrapped message to the first mix node in the selected path
  (await mixProto.sendPacket(nextHopPeerId, nextHopAddr, sphinxPacket, logConfig)).isOkOr:
    releaseAndFail(error)

  return ok(session)

proc reply(
    mixProto: MixProtocol, surb: SURB, msg: sink seq[byte]
) {.async: (raises: [CancelledError]).} =
  let (peerId, multiAddr) = surb.hop.get().bytesToMultiAddr().valueOr:
      error "could not obtain multiaddress from hop", err = error
      return

  # Reply messages don't require an application codec: routing is determined by the SURB.
  let message = buildMessage(move(msg), "").valueOr:
    error "could not build reply message", err = error
    return

  let sphinxPacket = useSURB(surb, message)

  let sendRes = await mixProto.sendPacket(
    peerId, multiAddr, sphinxPacket, SendPacketLogConfig(logType: Reply)
  )
  if sendRes.isErr:
    error "could not send reply", peerId, multiAddr, err = sendRes.error

type PathNode = object
  peerId: PeerId
  multiAddr: MultiAddress
  mixPubKey: FieldElement

proc selectRandomNodes(
    mixProto: MixProtocol, count: int, excludePeerIds: HashSet[PeerId]
): Result[seq[PathNode], string] {.raises: [].} =
  ## Select `count` random mix nodes from the pool, excluding specified peers.
  let available = mixProto.nodePool.peerIds().filterIt(it notin excludePeerIds)

  if available.len < count:
    return err(
      "Not enough mix nodes in pool (available=" & $available.len & ", needed=" & $count &
        ")"
    )

  let selectedPeerIds = mixProto.rng.pick(available, count).valueOr:
    return err("No mix nodes available in pool")

  var selected: seq[PathNode] = @[]
  for peerId in selectedPeerIds:
    let mixPubInfo = mixProto.nodePool.get(peerId).valueOr:
      return err("Could not get mix pub info for peer: " & $peerId)
    selected.add(
      PathNode(
        peerId: mixPubInfo.peerId,
        multiAddr: mixPubInfo.multiAddr,
        mixPubKey: mixPubInfo.mixPubKey,
      )
    )

  ok(selected)

proc buildCoverPacket*(
    mixProto: MixProtocol
): Result[CoverPacketBuild, string] {.raises: [].} =
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

  let (packetToSend, proofToken) = mixProto.generateAndAppendProof(
    sphinxPacket.serialize(), "Cover"
  ).valueOr:
    return err("Failed to generate proof for cover packet: " & error)

  let firstNode = nodes[0]
  ok(
    CoverPacketBuild(
      packet: packetToSend,
      firstHopPeerId: firstNode.peerId,
      firstHopAddr: firstNode.multiAddr,
      proofToken: proofToken,
    )
  )

proc sendCoverPacket*(
    mixProto: MixProtocol, peerId: PeerId, multiAddr: MultiAddress, packet: seq[byte]
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  try:
    await mixProto.writeLp(peerId, @[multiAddr], @[MixProtocolID], packet)
    mix_messages_forwarded.inc(labelValues = ["Cover"])
    return ok()
  except DialFailedError as exc:
    mix_messages_error.inc(labelValues = ["Cover", "SEND_FAILED"])
    return err("Failed to dial for cover packet: " & exc.msg)
  except LPStreamError as exc:
    mix_messages_error.inc(labelValues = ["Cover", "SEND_FAILED"])
    return err("Failed to write cover packet: " & exc.msg)

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
  ## When `spamProtection` is enabled, callers should prefer
  ## `SpamProtectionDelayStrategy` to avoid timing correlation between proof
  ## generation and short exponential delays.

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
  mixProto.nodePool = MixNodePool.new(switch.peerStore)
  mixProto.tagManager = tagManager
  mixProto.surbStore = store
  mixProto.destReadBehaviors = newTable[string, DestReadBehavior]()

  mixProto.spamProtection = spamProtection
  mixProto.delayStrategy = delayStrategy.valueOr:
    NoSamplingDelayStrategy.new(switch.rng)

  mixProto.coverTraffic = coverTraffic
  coverTraffic.withValue(ct):
    ct.setCoverPacketBuilder(
      proc(): Result[CoverPacketBuild, string] {.gcsafe, raises: [].} =
        mixProto.buildCoverPacket()
    )
    ct.setCoverPacketSender(
      proc(
          peerId: PeerId, multiAddr: MultiAddress, packet: seq[byte]
      ): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
        await mixProto.sendCoverPacket(peerId, multiAddr, packet)
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
    # For now: reply() takes `sink seq[byte]` and `move()`s into
    # buildMessage internally — the optimization stops at this boundary.
    await mixProto.reply(surb, message)

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
    surbStore,
  )
  mixProto
