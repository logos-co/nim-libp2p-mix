# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronicles, chronos, sequtils, results, sets
import std/[strformat, tables], metrics
import
  ./[
    curve25519, delay, padding, mix_message, mix_node, sphinx, serialization,
    tag_manager, mix_metrics, exit_layer, multiaddr, exit_connection, spam_protection,
    delay_strategy, pool, cover_traffic, surb_store, key_rotation,
  ]
import libp2p/protocols/protocol
import libp2p/stream/[connection, lpstream]
import libp2p/[switch, multicodec, peeraddrpolicy, peerinfo, varint]
import libp2p/crypto/crypto
import nimcrypto/utils # burnMem
import libp2p/utils/heartbeat

export pool
export SurbStore, SurbSession

when defined(enable_mix_benchmarks):
  import ./benchmark
  from times import getTime, toUnixFloat, `-`, initTime, `$`, inMilliseconds, Time
logScope:
  topics = "mix_protocol"

const MixProtocolID* = "/mix/1.0.0"

const CoverTrafficCodec* = "/mix/cover/1.0.0"
  ## Reserved codec for cover traffic packets. Cover packets use this codec
  ## so the exit node can identify and silently discard returning cover traffic.

const DefaultHopBackoff* = chronos.minutes(1)
  ## How long a first hop that failed a dial is not selected as the first hop.

const HopStreamDrainTimeout = chronos.seconds(5)
  ## How long a closed hop stream is still read while the next hop closes its
  ## side. It bounds how long `stop` waits for the hop streams.

const PoolSizeUpdateInterval = chronos.seconds(10)
  ## The timer of `mix_pool_size` counts the usable pool members this often, which
  ## is shorter than the usual scrape interval of a metrics server.

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
type
  MixDelivery* = object
    service*: string
    payload*: seq[byte]

  MixDeliveryHandler* =
    proc(delivery: MixDelivery): Future[void] {.async: (raises: [CancelledError]).}

  RawSurbReplyDisposition* {.pure.} = enum
    Unhandled
    Handled

  RawSurbReplyHandler* = proc(reply: RawSurbReply): Future[RawSurbReplyDisposition] {.
    async: (raises: [CancelledError])
  .}

  MixProtocol* = ref object of LPProtocol
    mixNodeInfo: MixNodeInfo
    switch*: Switch
    nodePool*: MixNodePool
    tagManager: TagManager
    exitLayer: ExitLayer
    rng: Rng
    surbStore: SurbStore
      ## Reply credentials for SURBs this node has issued. Expires entries whose
      ## reply never arrives; see surb_store.nim.
    deliveryHandlers: Table[string, MixDeliveryHandler]
    rawSurbReplyHandler: RawSurbReplyHandler
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
    hopReaders: Table[Connection, Future[void]]
      ## The `readHopStream` future of each hop stream, keyed by the stream that
      ## it reads, so that the reader of a stream can be found from the stream.
    hopDrainTimeout: Duration
      ## `HopStreamDrainTimeout`, kept in a field so that tests can shorten it.
    backedOffUntil: Table[PeerId, Moment]
      ## The moment until which a first hop that failed a dial is not the first hop.
    hopBackoff: Duration
    poolSizeLoop: Future[void] ## The timer that sets `mix_pool_size`.
    spamProtection: Opt[SpamProtection]
    delayStrategy: DelayStrategy
    coverTraffic*: Opt[CoverTraffic]
    keyRing: Opt[MixKeyRing]
    ongoingMixMessages: Table[uint64, Future[void]]
      ## In-flight handleMixMessages futures, cancelled on stop. Keyed so
      ## removal on completion is O(1).
    nextMixMessageId: uint64
    ongoingLocalSends: Table[uint64, FutureBase]
      ## In-flight local sends, cancelled on stop.
    nextLocalSendId: uint64

proc registerMixDeliveryHandler*(
    mixProto: MixProtocol, service: string, handler: MixDeliveryHandler
): Result[void, string] =
  ## Handlers must handle their own recoverable errors. The callback's async
  ## effect type permits only CancelledError, which propagates to the owner.
  if service.len == 0:
    return err("Mix delivery service must not be empty")

  if handler.isNil:
    return err("Mix delivery handler must not be nil")

  if mixProto.deliveryHandlers.hasKey(service):
    return err("Mix delivery handler is already registered for service: " & service)

  mixProto.deliveryHandlers[service] = handler
  ok()

proc unregisterMixDeliveryHandler*(mixProto: MixProtocol, service: string) =
  mixProto.deliveryHandlers.del(service)

proc registerRawSurbReplyHandler*(
    mixProto: MixProtocol, handler: RawSurbReplyHandler
): Result[void, string] =
  ## Each MixProtocol accepts one raw reply handler. A host with multiple
  ## plug-ins routes replies by identifier inside that handler. Return Unhandled
  ## for unknown identifiers so embedded connections can receive their replies.
  ## Handlers must handle their own recoverable errors. Only CancelledError may escape the callback; cancellation
  ## propagates instead of invoking the embedded-connection fallback.
  if handler.isNil:
    return err("raw SURB reply handler must not be nil")

  if not mixProto.rawSurbReplyHandler.isNil:
    return err("raw SURB reply handler is already registered")

  mixProto.rawSurbReplyHandler = handler
  ok()

proc unregisterRawSurbReplyHandler*(mixProto: MixProtocol) =
  mixProto.rawSurbReplyHandler = nil

proc hasDestReadBehavior*(mixProto: MixProtocol, codec: string): bool =
  return mixProto.destReadBehaviors.hasKey(codec)

proc registerDestReadBehavior*(
    mixProto: MixProtocol, codec: string, behavior: DestReadBehavior
) =
  mixProto.destReadBehaviors[codec] = behavior

func keyRotationEnabled*(mixProto: MixProtocol): bool {.raises: [].} =
  ## Whether this instance was configured with a key ring, even before startup.
  mixProto.keyRing.isSome()

proc ownMixPubKey(mixProto: MixProtocol): Result[FieldElement, string] {.raises: [].} =
  ## The public key for this node's own hop in a packet built now.
  let ring = mixProto.keyRing.valueOr:
    return ok(mixProto.mixNodeInfo.mixPubKey)
  let key = ring.currentPublicKey().valueOr:
    return err("No current mix key")
  ok(key)

proc localMixPubInfo*(
    mixProto: MixProtocol
): Result[MixPubInfo, string] {.raises: [].} =
  ## This node's record, with its current mix key. With a key ring there is no
  ## key before start or after stop, and the record is replaced at each rotation,
  ## so publish through the ring's key handler (Mix Key Rotation spec §4).
  var info = mixProto.mixNodeInfo.toMixPubInfo()
  info.mixPubKey = ?mixProto.ownMixPubKey()
  ok(info)

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
  let bound = uint64(max)
  let threshold = (0'u64 - bound) mod bound
  while true:
    let value = rng.generate(uint64)
    if value >= threshold:
      return ok(int(value mod bound))

proc runPoolSizeLoop(mixProto: MixProtocol) {.async: (raises: [CancelledError]).} =
  ## Sets `mix_pool_size` to the number of pool members that a path can use.
  ## The gauge is process-wide, so it shows the count of whichever `MixProtocol`
  ## counted last.
  heartbeat "Mix pool size", PoolSizeUpdateInterval:
    mix_pool_size.set(mixProto.nodePool.countUsable().int64)

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

proc readHopStream(conn: Connection) {.async: (raises: [CancelledError]).} =
  ## Read `conn` until it ends, and discard what it carries.
  ## This node only writes to a hop stream. libp2p 2.5 can return the stream
  ## of a dial before the next hop has acknowledged the protocol, and only a
  ## read takes that acknowledgement off the stream. An mplex connection
  ## delivers no other stream while the acknowledgement is unread.
  var buf: array[64, byte]
  try:
    while not conn.atEof:
      # The byte count is not needed: `handleMixNodeConnection` on the next hop
      # never writes, so the bytes are only libp2p's protocol acknowledgement.
      discard await conn.readOnce(addr buf[0], buf.len)
  except LPStreamError as e:
    trace "Hop stream ended", conn, err = e.msg

proc spawnHopReader(mixProto: MixProtocol, conn: Connection) =
  ## Start `readHopStream` for `conn`, track its future in `hopReaders`, and
  ## remove it from there when it finishes.
  let fut = readHopStream(conn)
  mixProto.hopReaders[conn] = fut
  fut.addCallback(
    proc(_: pointer) {.gcsafe, raises: [].} =
      mixProto.hopReaders.del(conn)
  )

proc retireHopStream(mixProto: MixProtocol, conn: Connection) {.async: (raises: []).} =
  ## Close `conn`, read it until the next hop closes its side, and cancel the
  ## reader if that takes longer than `hopDrainTimeout`.
  ## `close` ends only this node's side of the stream. Whatever the next hop
  ## sends after the reader is gone stays unread, and an mplex connection
  ## delivers no other stream while a frame is unread.
  if conn notin mixProto.hopReaders:
    # A stream from a dial that completed during `stop` has no reader.
    mixProto.spawnHopReader(conn)
  let reader = mixProto.hopReaders.getOrDefault(conn)
  await conn.close()
  try:
    discard await reader.withTimeout(mixProto.hopDrainTimeout)
  except CancelledError:
    # Cancelling `withTimeout` cancels the reader too, so the stream is
    # retired early rather than left with a reader.
    discard
  await reader.cancelAndWait()

proc removeClosedConnections(
    mixProto: MixProtocol, failed: Connection
) {.async: (raises: []).} =
  ## Take `failed` and the streams of disconnected peers out of the pool and
  ## retire them.
  var stale: seq[tuple[peerId: PeerId, conn: Connection]]
  for peerId, conn in mixProto.connPool:
    if conn == failed or not mixProto.switch.isConnected(peerId):
      stale.add((peerId, conn))
  for (peerId, _) in stale:
    mixProto.connPool.del(peerId)
  let retiring = stale.mapIt(mixProto.retireHopStream(it.conn))
  try:
    await allFutures(retiring)
  except CancelledError:
    await noCancel allFutures(retiring.mapIt(it.cancelAndWait()))

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
          mixProto.spawnHopReader(dial.value)
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
  ## for proof slot tracking. A proof that this procedure rejects is reclaimed
  ## here, because it never leaves this node.
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
    if proofResult.token.len > 0:
      spamProtection.reclaimProofToken(proofResult.token)
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
      if proofResult.token.len > 0:
        spamProtection.reclaimProofToken(proofResult.token)
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

type PacketKey = object
  ## The key a received packet was built for, found before its spam proof is
  ## verified.
  case rotating: bool
  of true:
    match: KeyMatch
  of false:
    sharedSecret: FieldElement

proc checkPacketKey(
    mixProto: MixProtocol, sphinxPacket: SphinxPacket
): Opt[PacketKey] {.raises: [].} =
  ## None when the packet is discarded; the reason is counted here.
  let ring = mixProto.keyRing.valueOr:
    var replay = checkReplay(
      sphinxPacket, mixProto.mixNodeInfo.mixPrivKey, mixProto.tagManager
    ).valueOr:
      error "Replay check failed", err = error
      mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_SPHINX"])
      return Opt.none(PacketKey)
    defer:
      burnMem(replay.sharedSecret)
    if replay.isReplay:
      mix_messages_error.inc(labelValues = ["Intermediate/Exit", "DUPLICATE"])
      return Opt.none(PacketKey)
    return Opt.some(PacketKey(rotating: false, sharedSecret: replay.sharedSecret))

  var match = matchKey(sphinxPacket, ring.candidates()).valueOr:
    error "Key matching failed", err = error
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "INVALID_SPHINX"])
    return Opt.none(PacketKey)
  defer:
    match.wipe()
  let reason =
    case match.status
    of KeyMatched:
      return Opt.some(PacketKey(rotating: true, match: match))
    of KeyReplayed:
      "DUPLICATE"
    of KeyTableFull:
      "REPLAY_CACHE_FULL"
    of NoKeyMatched:
      "INVALID_MAC"
  mix_messages_error.inc(labelValues = ["Intermediate/Exit", reason])
  Opt.none(PacketKey)

proc wipe(key: var PacketKey) {.raises: [].} =
  ## Processing wipes the shared secret only when it runs; this covers every
  ## other way out, such as a failed spam proof (Mix Key Rotation spec §3.3).
  if key.rotating:
    key.match.wipe()
  else:
    burnMem(key.sharedSecret)

proc processWithKey(
    mixProto: MixProtocol, sphinxPacket: SphinxPacket, key: var PacketKey
): Result[ProcessedSphinxPacket, string] {.raises: [].} =
  if key.rotating:
    processSphinxPacket(sphinxPacket, key.match)
  else:
    processSphinxPacket(
      sphinxPacket,
      mixProto.mixNodeInfo.mixPrivKey,
      mixProto.tagManager,
      Opt.some(key.sharedSecret),
    )

proc refundUnwritten(
    mixProto: MixProtocol, claimEpoch: uint64, proofToken: seq[byte] = @[]
) =
  ## Refund the slot of a packet that this node did not write, and reclaim its
  ## proof token if it has one. `unclaimSlot` requires the two together.
  if proofToken.len > 0 and mixProto.spamProtection.isSome:
    mixProto.spamProtection.get().reclaimProofToken(proofToken)
  if mixProto.coverTraffic.isSome:
    mixProto.coverTraffic.get().slotPool.unclaimSlot(claimEpoch)

proc refundCancelledHold(
    mixProto: MixProtocol,
    claimEpoch: uint64,
    proofGen: Future[Result[tuple[packet: seq[byte], proofToken: seq[byte]], string]],
) {.async: (raises: []).} =
  ## Refund a packet that was cancelled in its hold, the wait before its first
  ## dial. A proof can still finish after the cancel, so this procedure cancels
  ## the proof generation and waits for it to end. If the cancel ended it, the
  ## slot stays claimed, because the provider may have used the message ID.
  await proofGen.cancelAndWait()
  if proofGen.completed():
    let proved = proofGen.value()
    if proved.isOk:
      mixProto.refundUnwritten(claimEpoch, proved.get().proofToken)
    else:
      mixProto.refundUnwritten(claimEpoch)

type
  ReplyRecoveryErrorKind* {.pure.} = enum
    SphinxRecoveryFailed
    PayloadDecodingFailed

  ReplyRecoveryError* = object
    kind*: ReplyRecoveryErrorKind
    message*: string

proc decodeReplyPayload(recovered: seq[byte]): Result[seq[byte], string] =
  let unpadded = removePadding(recovered).valueOr:
    return err("invalid reply padding: " & error)

  let mixMessage = MixMessage.deserialize(unpadded).valueOr:
    return err("invalid reply message: " & error)

  if mixMessage.codec.len > 0:
    return err("unexpected codec in SURB reply")

  ok(mixMessage.message)

proc recoverReply*(
    credential: ReplyCredential, reply: RawSurbReply
): Result[seq[byte], ReplyRecoveryError] =
  let recovered = recoverSphinxReply(credential, reply).valueOr:
    return err(
      ReplyRecoveryError(
        kind: ReplyRecoveryErrorKind.SphinxRecoveryFailed, message: error
      )
    )

  let payload = decodeReplyPayload(recovered).valueOr:
    return err(
      ReplyRecoveryError(
        kind: ReplyRecoveryErrorKind.PayloadDecodingFailed, message: error
      )
    )

  ok(payload)

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

  var packetKey = mixProto.checkPacketKey(sphinxPacket).valueOr:
    return
  defer:
    packetKey.wipe()

  # Step 3: Verify spam proof
  # Only done after replay check passes to avoid wasting cycles on duplicates
  (await mixProto.verifyProof(sphinxBytes, spamProof, "Intermediate/Exit")).isOkOr:
    error "Spam protection verification failed", err = error
    return

  # The matched key's grace window can end while the proof is verified.
  if packetKey.rotating and not packetKey.match.key.isAccepted(Moment.now()):
    debug "Mix key expired before processing"
    mix_messages_error.inc(labelValues = ["Intermediate/Exit", "EXPIRED_KEY"])
    return

  # Step 4: Full Sphinx processing
  # Reuse the shared secret computed in step 2 to avoid duplicate EC multiplication
  var processedSP = mixProto.processWithKey(sphinxPacket, packetKey).valueOr:
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
      if mixProto.coverTraffic.isSome:
        mixProto.coverTraffic.get().onCoverReceived()
      return

    if processedSP.destination == Hop():
      # Keep a local copy so unregistering concurrently only affects later
      # deliveries. A registered service owns the payload in its entirety;
      # the legacy SURB envelope is not interpreted on this path.
      let deliveryHandler = mixProto.deliveryHandlers.getOrDefault(deserialized.codec)
      if not deliveryHandler.isNil:
        await deliveryHandler(
          MixDelivery(service: deserialized.codec, payload: deserialized.message)
        )
        mix_messages_forwarded.inc(labelValues = ["Exit"])
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

    let rawReply = RawSurbReply(
      identifier: processedSP.id, encryptedPayload: move(processedSP.delta_prime)
    )

    # Keep a local copy so unregistering concurrently only affects subsequent
    # deliveries. A handler owns the reply only when it recognizes its id.
    let rawReplyHandler = mixProto.rawSurbReplyHandler
    if not rawReplyHandler.isNil and
        (await rawReplyHandler(rawReply)) == RawSurbReplyDisposition.Handled:
      return

    # No plug-in recognized this reply, so preserve the embedded connection path.
    # Expired credentials are invisible here even if no sweep has run yet.
    let connCred = mixProto.surbStore.get(rawReply.identifier).valueOr:
      mix_messages_error.inc(labelValues = ["Sender/Reply", "NO_CONN_FOUND"])
      return

    let payload = recoverReply(connCred.credential, rawReply).valueOr:
      case error.kind
      of ReplyRecoveryErrorKind.SphinxRecoveryFailed:
        error "could not recover Sphinx reply", id = processedSP.id, err = error.message
        mix_messages_error.inc(labelValues = ["Reply", "INVALID_CREDS"])
      of ReplyRecoveryErrorKind.PayloadDecodingFailed:
        # Consume only this malformed reply; other SURBs are independent.
        mixProto.surbStore.release(processedSP.id)
        error "could not decode reply payload", id = processedSP.id, err = error.message
        mix_messages_error.inc(labelValues = ["Reply", "INVALID_SPHINX"])
      return

    # Each SURB is single-use; other blocks can still deliver their replies.
    mixProto.surbStore.release(processedSP.id)

    when defined(enable_mix_benchmarks):
      benchmarkLog "Reply",
        mixProto.switch.peerInfo.peerId,
        startTime,
        metadata,
        Opt.some(fromPeerId),
        Opt.none(PeerId)

    await connCred.incoming.put(payload)
  of Intermediate:
    trace "Intermediate node processing",
      peerId = mixProto.mixNodeInfo.peerId, multiAddr = mixProto.mixNodeInfo.multiAddr
    mix_messages_recvd.inc(labelValues = ["Intermediate"])

    # Claim a slot for forwarding (Mix Cover Traffic spec §6.4)
    var claimEpoch: uint64
    if mixProto.coverTraffic.isSome:
      let ct = mixProto.coverTraffic.get()
      let claim = ct.slotPool.claimSlot()
      if not claim.success:
        warn "Slot exhaustion, dropping forwarded packet"
        mix_messages_error.inc(labelValues = ["Intermediate", "SLOT_EXHAUSTED"])
        mix_slot_claim_rejected.inc(labelValues = ["forward"])
        return
      claimEpoch = ct.slotPool.epoch
      # Reclaim proof token from discarded cover packet for messageId reuse
      if claim.reclaimedToken.len > 0 and mixProto.spamProtection.isSome:
        mixProto.spamProtection.get().reclaimProofToken(claim.reclaimedToken)

    let actualDelay = mixProto.delayStrategy.generateForIntermediate(processedSP.delay)
    trace "Computed delay", encodedDelay = processedSP.delay, actualDelay

    # Forward to next hop
    let nextHopBytes = processedSP.nextHop.get()

    let (nextPeerId, nextAddr) = bytesToMultiAddr(nextHopBytes).valueOr:
      trace "Failed to convert bytes to multiaddress", err = error
      mix_messages_error.inc(labelValues = ["Intermediate", "INVALID_DEST"])
      mixProto.refundUnwritten(claimEpoch)
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
    try:
      await allFutures(proofGenFut, delayFut)
    except CancelledError as e:
      await mixProto.refundCancelledHold(claimEpoch, proofGenFut)
      raise e

    if mixProto.spamProtection.isSome and proofGenTimeMs > actualDelay.int64:
      warn "Proof generation time exceeds sampled delay",
        proofGenTimeMs,
        sampledDelay = actualDelay,
        hint = "Increase the minimum delay floor or reduce proof generation time"

    let (outgoingPacket, proofToken) = (await proofGenFut).valueOr:
      error "Failed to generate spam protection proof for next hop", err = error
      mixProto.refundUnwritten(claimEpoch)
      return

    # A packet whose first dial failed or was cancelled never left this node, so
    # its slot can be refunded and its messageId reused. After any write attempt the
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
        mixProto.refundUnwritten(claimEpoch, proofToken)
        return
      except CancelledError as e:
        mixProto.refundUnwritten(claimEpoch, proofToken)
        raise e

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

proc payloadCapacity(codec: string, envelopeSize: int): Result[int, string] =
  let capacity = DataSize - serializedLen(codec, 0) - envelopeSize
  if capacity < 0:
    return err("cannot encode messages for this codec")
  ok(capacity)

proc getMaxServicePayloadSize*(service: string): Result[int, string] =
  ## Maximum opaque payload accepted by the message-oriented send overloads.
  if service.len == 0:
    return err("Mix service must not be empty")
  payloadCapacity(service, 0)

proc getMaxMessageSizeForCodec*(
    codec: string, numberOfSurbs: uint8 = 0
): Result[int, string] =
  ## Computes the maximum payload size (in bytes) available for a message when encoded  
  ## with the given `codec`, optionally including space for the chosen number of surbs.  
  ## Returns an error if the codec + surb overhead exceeds the data capacity.  
  payloadCapacity(codec, SurbLenSize + int(numberOfSurbs) * SurbSize)

proc drawUsable(
    mixProto: MixProtocol, peerIds: var seq[PeerId], label: string
): Result[MixHop, string] {.gcsafe, raises: [].} =
  ## Draws peers from `peerIds` until the pool has a hop address for one, and
  ## removes each peer that it draws. So each peer that a path can use has the
  ## same chance, and a peer with no hop address keeps its mix key.
  ## If it runs out of peers, it counts a `LOW_MIX_POOL` error under `label`.
  while peerIds.len > 0:
    let index = ?cryptoRandomInt(mixProto.rng, peerIds.len)
    let peerId = peerIds[index]
    peerIds.del(index)
    let mixHop = mixProto.nodePool.getHop(peerId)
    if mixHop.isSome:
      return ok(mixHop.get())
  mix_messages_error.inc(labelValues = [label, "LOW_MIX_POOL"])
  err("Ran out of usable mix nodes")

proc drawHops(
    mixProto: MixProtocol, peerIds: openArray[PeerId], count: int, label: string
): Result[seq[MixHop], string] {.raises: [].} =
  ## Draws `count` usable pool members from `peerIds`, skipping backed off peers for
  ## the first hop only.
  var candidates = @peerIds
  # The backed off peers that the draw of the first hop skipped.
  var skipped: seq[PeerId]
  var hops: seq[MixHop]
  while hops.len < count:
    let mixHop = ?mixProto.drawUsable(candidates, label)
    if hops.len == 0:
      if mixProto.hopIsBackedOff(mixHop.info.peerId):
        skipped.add(mixHop.info.peerId)
        continue
      # Peers skipped for the first hop are fine as later hops.
      candidates.add(skipped)
    hops.add(mixHop)
  ok(hops)

type SurbBuild* = object
  surb*: SURB
  credential*: ReplyCredential
  dispatchBefore*: Opt[Moment]
    ## Send the packet carrying this SURB before the oldest path record is stale.
  replyTransitAllowance*: Opt[Duration]
    ## Budget for supply delivery and reply transit under the rotation configuration.
  replyHoldTime*: Opt[Duration]
    ## Maximum time a receiver may retain a freshly dispatched SURB.
  credentialsExpireAt*: Opt[Moment]
    ## When the reply credentials must be unrecoverable: G - D after obtaining
    ## the oldest record of the other hops on the SURB's return path (Mix Key
    ## Rotation spec §7), none without a key ring

method buildSurb*(
    mixProto: MixProtocol, id: SURBIdentifier, destPeerId: PeerId, exitPeerId: PeerId
): Result[SurbBuild, string] {.base, gcsafe, raises: [].} =
  var
    publicKeys: seq[FieldElement] = @[]
    hops: seq[Hop] = @[]
    delays: seq[Delay] = @[]
    pathPeerIds: seq[PeerId] = @[]

  # Remove exit and dest node from nodes to consider for surbs
  var poolPeerIds =
    mixProto.nodePool.peerIds().filterIt(it != exitPeerId and it != destPeerId)

  # The last hop of a reply path is this node, so the pool supplies only the others.
  if poolPeerIds.len < PathLength - 1:
    mix_messages_error.inc(labelValues = ["Entry/SURB", "LOW_MIX_POOL"])
    return err(
      "Not enough mix nodes for a reply path (available=" & $poolPeerIds.len &
        ", needed=" & $(PathLength - 1) & ")"
    )

  # Draw the hops at random, and then add this node as the last hop.
  for i in 0 ..< PathLength:
    let (mixPubKey, multiAddrBytes, hopDelay) =
      if i < PathLength - 1:
        let mixHop = mixProto.drawUsable(poolPeerIds, "Entry/SURB").valueOr:
          return err(error)
        debug "Selected mix node for surbs: ", indexInPath = i
        pathPeerIds.add(mixHop.info.peerId)
        (
          mixHop.info.mixPubKey,
          mixHop.addrBytes,
          mixProto.delayStrategy.generateForEntry(),
        )
      else:
        let selfAddrBytes = multiAddrToBytes(
          mixProto.mixNodeInfo.peerId, mixProto.mixNodeInfo.multiAddr
        ).valueOr:
          mix_messages_error.inc(labelValues = ["Entry/SURB", "INVALID_MIX_INFO"])
          return err("failed to convert multiaddress to bytes: " & error)
        (?mixProto.ownMixPubKey(), selfAddrBytes, NoDelay) # No delay for last hop

    publicKeys.add(mixPubKey)

    hops.add(Hop.init(multiAddrBytes))

    delays.add(hopDelay)

  var created = ?createSURB(publicKeys, delays, hops, id, mixProto.rng)
  let ring = mixProto.keyRing.valueOr:
    return ok(SurbBuild(surb: move(created.surb), credential: move(created.credential)))
  # The packet carrying the SURB is sent before the oldest of these records goes
  # stale, and the SURB's keys remain accepted for surbLifetime after sending,
  # so every reply arrives by then: G - D after obtaining that record (Mix Key
  # Rotation spec §5, §7).
  ok(
    SurbBuild(
      surb: move(created.surb),
      credential: move(created.credential),
      dispatchBefore: mixProto.nodePool.staleAt(pathPeerIds),
      replyHoldTime: Opt.some(ring.config.surbHoldTime),
      replyTransitAllowance:
        Opt.some(ring.config.surbLifetime - ring.config.surbHoldTime),
      credentialsExpireAt: mixProto.nodePool.staleAt(pathPeerIds).map(
          proc(staleAt: Moment): Moment =
            staleAt + ring.config.surbLifetime
        ),
    )
  )

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

    var built = mixProto.buildSurb(id, destPeerId, exitPeerId).valueOr:
      # Release whatever this group already registered; a partially built
      # group can never receive a usable reply.
      session.release()
      return err(error)
    if built.credentialsExpireAt.isSome:
      session.igroup.expireBy(built.credentialsExpireAt.get())

    # The per-hop secrets move out of the SURB, and the store keeps the only
    # copy of the credentials, so none is left unwiped (Mix Key Rotation spec
    # §7). The reply key stays in the SURB for the exit.
    var creds = ConnCreds(
      igroup: session.igroup, incoming: incoming, credential: move(built.credential)
    )
    let added = mixProto.surbStore.add(id, move(creds))
    added.isOkOr:
      session.release()
      return err(error)

    response.add(built.surb)

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
    claimEpoch: uint64,
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  ## Send the wrapped message to the first mix node in the selected path.
  ## Applies the sender pre-send delay (mix.md §8.5.2 step 3.f) before the
  ## first-hop write to break burst timing correlation.
  ##
  ## `claimEpoch` is the epoch of the caller's slot claim. The slot is refunded
  ## if nothing was written.

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
  try:
    await allFutures(proofGenFut, delayFut)
  except CancelledError as e:
    await mixProto.refundCancelledHold(claimEpoch, proofGenFut)
    raise e

  if mixProto.spamProtection.isSome and proofGenTimeMs > initialDelay.int64:
    warn "Proof generation time exceeds sampled sender delay",
      proofGenTimeMs,
      sampledDelay = initialDelay,
      hint = "Increase the minimum delay floor or reduce proof generation time"

  let (packetToSend, proofToken) = (await proofGenFut).valueOr:
    mixProto.refundUnwritten(claimEpoch)
    return err(error)

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

  # A packet whose first dial failed or was cancelled never left this node, so
  # its messageId can be reused. After any write attempt the next hop may hold the
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
      mixProto.refundUnwritten(claimEpoch, proofToken)
      return err(fmt"Failed to dial to next hop ({peerId}, {multiAddress}): {exc.msg}")
    except CancelledError as e:
      mixProto.refundUnwritten(claimEpoch, proofToken)
      raise e

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
    return err(fmt"Failed to redial next hop ({peerId}, {multiAddress}): {exc.msg}")
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

proc exitNode*(T: typedesc[MixDestination], p: PeerId): T =
  T(kind: DestinationType.MixNode, peerId: p)

proc forwardToAddr*(T: typedesc[MixDestination], p: PeerId, address: MultiAddress): T =
  T(kind: DestinationType.ForwardAddr, peerId: p, address: address)

proc init*(T: typedesc[MixDestination], p: PeerId, address: MultiAddress): T =
  MixDestination.forwardToAddr(p, address)

proc createSurb*(
    mixProto: MixProtocol, destination: MixDestination
): Result[SurbBuild, string] =
  ## Create a reply block that returns to this Mix node. The destination is
  ## excluded from the independently selected return path. Move the credential
  ## into its owner and wipe it on use, by credentialsExpireAt when present,
  ## or on shutdown, whichever comes first.
  if destination.kind != MixNode:
    return err("SURBs require exit == destination")

  var id: SURBIdentifier
  mixProto.rng.generate(id)
  mixProto.buildSurb(id, destination.peerId, destination.peerId)

proc sendLocal(
    mixProto: MixProtocol,
    incoming: AsyncQueue[seq[byte]],
    msg: sink seq[byte],
    codec: string,
    destination: MixDestination,
    numSurbs: uint8,
    useLegacySurbEnvelope: bool,
    destinationInfo: Opt[MixPubInfo] = Opt.none(MixPubInfo),
): Future[Result[Opt[SurbSession], string]] {.
    async: (raises: [CancelledError, LPStreamError])
.} =
  ## On success returns a handle to the reply credentials registered for this
  ## send (or `Opt.none` when `numSurbs == 0`), so the caller can release them
  ## promptly when its connection closes.
  mix_messages_recvd.inc(labelValues = ["Entry"])
  let envelopeSize =
    if useLegacySurbEnvelope:
      SurbLenSize + int(numSurbs) * SurbSize
    else:
      0
  let capacity = payloadCapacity(codec, envelopeSize).valueOr:
    mix_messages_error.inc(labelValues = ["Entry", "INVALID_SIZE"])
    return err(error)
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

  var candidates = mixProto.nodePool.peerIds()

  # The draw never picks the destination.
  let index = candidates.find(destination.peerId)
  if index != -1:
    candidates.del(index)

  # A destination that is a mix node is itself the last hop, so only the hops before
  # it are drawn.
  let lastHop =
    if destinationInfo.isSome:
      let info = destinationInfo.get()
      let mixHop = mixProto.nodePool.getHop(info).valueOr:
        mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
        return err("Explicit Mix destination has no usable address")
      Opt.some(mixHop)
    elif destination.kind == MixNode:
      let mixHop = mixProto.nodePool.getHop(destination.peerId).valueOr:
        mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
        return err(
          "Destination is not a mix node with a usable address and a current record"
        )
      Opt.some(mixHop)
    else:
      Opt.none(MixHop)
  let drawCount =
    if lastHop.isSome():
      PathLength - 1
    else:
      PathLength

  if candidates.len < drawCount:
    mix_messages_error.inc(labelValues = ["Entry", "LOW_MIX_POOL"])
    return err(
      "Not enough mix nodes for a send (available=" & $candidates.len & ", needed=" &
        $drawCount & ")"
    )

  var pathHops = ?mixProto.drawHops(candidates, drawCount, "Entry")
  if lastHop.isSome:
    pathHops.add(lastHop.get())

  let nextHopPeerId = pathHops[0].info.peerId
  let nextHopAddr = pathHops[0].info.multiAddr
  let exitPeerId = pathHops[^1].info.peerId
  for i, mixHop in pathHops:
    debug "Selected mix node: ", indexInPath = i
    publicKeys.add(mixHop.info.mixPubKey)
    delays.add(
      if i != PathLength - 1:
        mixProto.delayStrategy.generateForEntry()
      else:
        NoDelay
    )
    hop.add(Hop.init(mixHop.addrBytes))

  # Encode destination
  let destHop =
    if destination.kind == ForwardAddr:
      let destAddrBytes = multiAddrToBytes(destination.peerId, destination.address).valueOr:
        mix_messages_error.inc(labelValues = ["Entry", "INVALID_DEST"])
        return err(fmt"Failed to convert multiaddress to bytes: {error}")
      Hop.init(destAddrBytes)
    else:
      Hop()

  var prepared =
    if useLegacySurbEnvelope:
      mixProto.prepareMsgWithSurbs(
        incoming, move(msg), numSurbs, destination.peerId, exitPeerId
      ).valueOr:
        return err(fmt"Could not prepend SURBs: {error}")
    else:
      (msg: move(msg), session: Opt.none(SurbSession))

  let session = prepared.session

  # Past this point the reply credentials are registered. The caller gets the
  # handle to them only when the send completes, so every other exit, a
  # failure or a cancellation, releases them here.
  var sent = false
  defer:
    if not sent:
      session.get(nil).release()

  let message = buildMessage(move(prepared.msg), codec).valueOr:
    mix_messages_error.inc(labelValues = ["Entry", error[1]])
    return err(fmt"Error building message: {error[0]}")

  # Wrap in Sphinx packet
  let sphinxPacket = wrapInSphinxPacket(message, publicKeys, delays, hop, destHop).valueOr:
    mix_messages_error.inc(labelValues = ["Entry", "NON_RECOVERABLE"])
    return err(fmt"Failed to wrap in sphinx packet: {error}")

  # Claim a slot for local origination (Mix Cover Traffic spec §6.3).
  # Claimed here rather than on entry so that validation failures above never
  # consume a slot.
  var claimEpoch: uint64
  if mixProto.coverTraffic.isSome:
    let ct = mixProto.coverTraffic.get()
    let claim = ct.slotPool.claimSlot()
    if not claim.success:
      mix_slot_claim_rejected.inc(labelValues = ["send"])
      return err("No slots available in current epoch")
    claimEpoch = ct.slotPool.epoch
    # Reclaim proof token from discarded cover packet for messageId reuse
    if claim.reclaimedToken.len > 0 and mixProto.spamProtection.isSome:
      mixProto.spamProtection.get().reclaimProofToken(claim.reclaimedToken)

  # Send the wrapped message to the first mix node in the selected path
  (
    await mixProto.sendPacket(
      nextHopPeerId, nextHopAddr, sphinxPacket, logConfig, claimEpoch
    )
  ).isOkOr:
    return err(error)

  sent = true
  return ok(session)

proc sendInternal(
    mixProto: MixProtocol,
    incoming: AsyncQueue[seq[byte]],
    msg: sink seq[byte],
    codec: string,
    destination: MixDestination,
    numSurbs: uint8,
    useLegacySurbEnvelope: bool,
    destinationInfo: Opt[MixPubInfo] = Opt.none(MixPubInfo),
): Future[Result[Opt[SurbSession], string]] {.
    async: (raises: [CancelledError, LPStreamError])
.} =
  ## On success returns a handle to the reply credentials registered for this
  ## send (or `Opt.none` when `numSurbs == 0`), so the caller can release them
  ## promptly when its connection closes. A send that a protocol stop cancels
  ## returns an error.
  let caller = if useLegacySurbEnvelope: "anonymizeLocalProtocolSend" else: "send"
  if not mixProto.started:
    return err(caller & ": mix protocol is not running")
  let pending = mixProto.sendLocal(
    incoming,
    move(msg),
    codec,
    destination,
    numSurbs,
    useLegacySurbEnvelope,
    destinationInfo,
  )
  let id = mixProto.nextLocalSendId
  mixProto.nextLocalSendId.inc()
  mixProto.ongoingLocalSends[id] = FutureBase(pending)
  try:
    return await pending
  except CancelledError as exc:
    # `stop` cancels each pending send. The caller did not, so it gets an error.
    if not mixProto.started:
      return err(caller & ": mix protocol has stopped")
    raise exc
  finally:
    mixProto.ongoingLocalSends.del(id)

proc sendSurbReply*(
    mixProto: MixProtocol, surb: SURB, msg: sink seq[byte]
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  if not mixProto.started:
    return err("sendSurbReply: mix protocol is not running")
  let (peerId, multiAddr) = surb.hop.get().bytesToMultiAddr().valueOr:
      return err("could not obtain multiaddress from hop: " & $error)

  # Reply messages don't require an application codec: routing is determined by the SURB.
  let message = buildMessage(move(msg), "").valueOr:
    return err("could not build reply message: " & error[0])

  let sphinxPacket = useSURB(surb, message)

  var claimEpoch: uint64
  if mixProto.coverTraffic.isSome:
    let ct = mixProto.coverTraffic.get()
    let claim = ct.slotPool.claimSlot()
    if not claim.success:
      mix_slot_claim_rejected.inc(labelValues = ["reply"])
      return err("No slots available in current epoch")
    claimEpoch = ct.slotPool.epoch
    if claim.reclaimedToken.len > 0 and mixProto.spamProtection.isSome:
      mixProto.spamProtection.get().reclaimProofToken(claim.reclaimedToken)

  (
    await mixProto.sendPacket(
      peerId, multiAddr, sphinxPacket, SendPacketLogConfig(logType: Reply), claimEpoch
    )
  ).isOkOr:
    return err("could not send reply: " & error)
  return ok()

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
  ## Legacy request/reply send. New message-oriented consumers should use
  ## `send`, supplying and owning their SURBs separately.
  await mixProto.sendInternal(incoming, move(msg), codec, destination, numSurbs, true)

proc send*(
    mixProto: MixProtocol,
    destination: MixDestination,
    service: string,
    payload: sink seq[byte],
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  ## Send one opaque payload to a service at a Mix destination. This operation
  ## creates no reply credentials and applies no legacy SURB envelope.
  if service.len == 0:
    return err("Mix service must not be empty")

  if destination.kind != MixNode:
    return err("Mix service delivery requires exit == destination")

  try:
    (await mixProto.sendInternal(nil, move(payload), service, destination, 0, false)).isOkOr:
      return err(error)
  except LPStreamError as exc:
    return err("could not send Mix service payload: " & exc.msg)

  ok()

proc send*(
    mixProto: MixProtocol,
    destination: MixPubInfo,
    service: string,
    payload: sink seq[byte],
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  ## Use the supplied address for the final hop. With key rotation enabled,
  ## the supplied Mix public key must match a locally unexpired pool record
  ## for the destination peer. With rotation disabled, the destination may
  ## be outside the pool. This send leaves the pool and peer store unchanged
  ## and excludes the destination when selecting the preceding hops.
  if service.len == 0:
    return err("Mix service must not be empty")
  discard multiAddrToBytes(destination.peerId, destination.multiAddr).valueOr:
    return err("Invalid explicit Mix destination address: " & error)
  try:
    (
      await mixProto.sendInternal(
        nil,
        move(payload),
        service,
        MixDestination.exitNode(destination.peerId),
        0,
        false,
        Opt.some(destination),
      )
    ).isOkOr:
      return err(error)
  except LPStreamError as exc:
    return err("could not send Mix service payload: " & exc.msg)
  ok()

proc sendWithSurb*(
    mixProto: MixProtocol, surb: sink SURB, payload: sink seq[byte]
): Future[Result[void, string]] {.async: (raises: [CancelledError]).} =
  ## Send one opaque payload through a caller-supplied SURB. The caller must
  ## treat the SURB as consumed once it invokes this operation, including when
  ## the result is an error.
  let pending = mixProto.sendSurbReply(surb, move(payload))
  let id = mixProto.nextLocalSendId
  mixProto.nextLocalSendId.inc()
  mixProto.ongoingLocalSends[id] = FutureBase(pending)
  try:
    return await pending
  except CancelledError as e:
    if not mixProto.started:
      return err("sendWithSurb: mix protocol has stopped")
    raise e
  finally:
    mixProto.ongoingLocalSends.del(id)

proc selectRandomNodes(
    mixProto: MixProtocol, count: int, excludePeerIds: HashSet[PeerId]
): Result[seq[MixHop], string] {.raises: [].} =
  let available = mixProto.nodePool.peerIds().filterIt(it notin excludePeerIds)
  if available.len < count:
    mix_messages_error.inc(labelValues = ["Cover", "LOW_MIX_POOL"])
    return err(
      "Not enough mix nodes in pool (available=" & $available.len & ", needed=" & $count &
        ")"
    )

  mixProto.drawHops(available, count, "Cover")

proc buildCoverPacket*(
    mixProto: MixProtocol, epoch: uint64
): Future[Result[CoverPacketBuild, string]] {.async: (raises: [CancelledError]).} =
  ## Build a cover Sphinx packet with a loop path (self = exit node),
  ## random payload .
  let nodes = mixProto.selectRandomNodes(
    PathLength - 1, [mixProto.mixNodeInfo.peerId].toHashSet
  ).valueOr:
    return err(error)
  let recordsStaleAt = mixProto.nodePool.staleAt(nodes.mapIt(it.info.peerId))

  var
    publicKeys: seq[FieldElement] = @[]
    hops: seq[Hop] = @[]
    delays: seq[Delay] = @[]

  for node in nodes:
    publicKeys.add(node.info.mixPubKey)
    hops.add(Hop.init(node.addrBytes))
    delays.add(mixProto.delayStrategy.generateForEntry())

  let selfAddrBytes = multiAddrToBytes(
    mixProto.mixNodeInfo.peerId, mixProto.mixNodeInfo.multiAddr
  ).valueOr:
    return err("Failed to convert self multiaddress to bytes: " & error)
  publicKeys.add(?mixProto.ownMixPubKey())
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
      firstHopPeerId: firstNode.info.peerId,
      firstHopAddr: firstNode.info.multiAddr,
      proofToken: proofToken,
      recordsStaleAt: recordsStaleAt,
    )
  )

proc buildCoverPacket*(
    mixProto: MixProtocol
): Future[Result[CoverPacketBuild, string]] {.async: (raises: [CancelledError]).} =
  var epoch: uint64
  if mixProto.coverTraffic.isSome:
    epoch = mixProto.coverTraffic.get().slotPool.epoch
  return await mixProto.buildCoverPacket(epoch)

proc generateAndAppendCoverProof(
    mixProto: MixProtocol, packet: seq[byte], epoch: Opt[uint64]
): Future[Result[CoverProofResult, string]] {.async: (raises: [CancelledError]).} =
  if mixProto.spamProtection.isSome() and
      not mixProto.spamProtection.get().precomputeCoverProofs():
    let proved = await mixProto.generateAndAppendProof(packet, "Cover", epoch)
    return proved.map(
      proc(value: auto): CoverProofResult =
        CoverProofResult(packet: value.packet, proofToken: value.proofToken)
    )
  return ok(CoverProofResult(packet: packet))

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
  if not mixProto.started:
    return err("sendCoverPacket: mix protocol is not running")
  let proved = (await mixProto.generateAndAppendCoverProof(packet, epoch)).valueOr:
    return err(error)
  return await mixProto.writeCoverPacket(peerId, multiAddr, proved.packet)

method start*(mixProto: MixProtocol) {.async: (raises: [CancelledError]).} =
  await procCall LPProtocol(mixProto).start()
  if mixProto.keyRing.isSome():
    mixProto.keyRing.get().start()
  mixProto.tagManager.start()
  mixProto.surbStore.start()
  if mixProto.poolSizeLoop.isNil or mixProto.poolSizeLoop.finished:
    mixProto.poolSizeLoop = mixProto.runPoolSizeLoop()
  if mixProto.coverTraffic.isSome:
    await mixProto.coverTraffic.get().start()

method stop*(mixProto: MixProtocol) {.async: (raises: []).} =
  ## Stop the cover traffic, cancel the hop dials, the pending sends and the
  ## in-flight handleMixMessages futures, retire the hop streams, then stop the
  ## `mix_pool_size` timer and the stores.
  if mixProto.coverTraffic.isSome:
    await mixProto.coverTraffic.get().stop()
  mixProto.started = false

  # The dials go first. A send that waits on its first dial then ends on its
  # dial failure path, which refunds its slot and its proof.
  # An entry of `dialing` is the future of a dial and the addresses of that dial.
  # The mapIt takes the futures, and the stop cancels them below.
  let dials = toSeq(mixProto.dialing.values).mapIt(it.dial)
  if dials.len > 0:
    await noCancel allFutures(dials.mapIt(it.cancelAndWait()))
  # A stream from a dial that completed during the stop is not in the pool.
  let dialed = dials.filterIt(it.completed()).mapIt(it.value)

  # Cancelling makes each send and each handler delete its own entry.
  let pending =
    toSeq(mixProto.ongoingLocalSends.values) &
    toSeq(mixProto.ongoingMixMessages.values).mapIt(FutureBase(it))
  mixProto.ongoingLocalSends.clear()
  mixProto.ongoingMixMessages.clear()
  if pending.len > 0:
    await noCancel allFutures(pending.mapIt(it.cancelAndWait()))

  let streams = toSeq(mixProto.connPool.values) & dialed
  mixProto.connPool.clear()
  if streams.len > 0:
    await noCancel allFutures(streams.mapIt(mixProto.retireHopStream(it)))

  if not mixProto.poolSizeLoop.isNil:
    await mixProto.poolSizeLoop.cancelAndWait()

  await mixProto.tagManager.stop()

  if mixProto.keyRing.isSome():
    await mixProto.keyRing.get().stop()

  await mixProto.surbStore.stop()
  mixProto.surbStore.clear()

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
    hopAddressPolicy: PeerAddressPolicy = defaultAddressPolicy,
    keyRing: Opt[MixKeyRing] = Opt.none(MixKeyRing),
) {.raises: [].} =
  ## Initialize a MixProtocol instance.
  ##
  ## A nil `surbStore` gets a default one, which with a `keyRing` purges every
  ## tenth of the SURB lifetime; a supplied store keeps its own purge interval.
  ## Defaulting to nil rather than `SurbStore.new()` keeps the constructor out
  ## of the parameter list, so callers do not need `surb_store`'s `new` in scope.
  ##
  ## With a `keyRing` the node rotates its mix key (Mix Key Rotation spec), and
  ## start and stop also start and stop the ring; stopping destroys its keys.
  ## Paths then use only nodes whose MixPubKeyBook entry was set within the
  ## rotation interval, so mix keys must come from discovery, not from
  ## configuration or the node's own storage. Without one it uses
  ## `mixNodeInfo.mixPrivKey` and `tagManager`.
  ##
  ## Mix node public keys should be populated via the nodePool after
  ## initialization using `mixProto.nodePool.add(mixPubInfo)`.
  ##
  ## `hopAddressPolicy` decides which of a pool member's addresses Mix can use as
  ## its hop address. This node leaves a pool member off every path it builds
  ## while the policy accepts none of its addresses. The default policy accepts
  ## any address, and so does a nil policy.
  ##
  ## The policy does not apply to the address of this node or to a destination
  ## address, because the library does not select these addresses. The host
  ## gives the address of this node in `mixNodeInfo` or with
  ## `setLocalMultiAddr`. The caller of a send gives the destination address.
  ## In each case the library has one address and no other address to use in
  ## its place. So the host makes sure that other nodes can dial the address
  ## of this node. If they cannot, no reply and no cover packet comes back to
  ## this node. A destination that is a mix node has no address from the
  ## caller. It is a pool member, so the policy applies to it.
  ##
  ## The policy also does not apply to an address that this node reads from
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
  ##
  ## From `start` to `stop`, a timer sets `mix_pool_size` to the number of pool
  ## members that a path can use, once per `PoolSizeUpdateInterval`.

  doAssert not switch.rng.isNil, "Switch must have RNG initialized"

  var
    maxRecordAge = Opt.none(Duration)
    surbHoldTime = Opt.none(Duration)
    purgeInterval = DefaultSurbCredsPurgeInterval
  if keyRing.isSome():
    let ring = keyRing.get()
    maxRecordAge = Opt.some(ring.config.rotationInterval)
    surbHoldTime = Opt.some(ring.config.surbHoldTime)
    # The default store keeps expired credentials until its next purge, so they
    # outlive their expiry by at most a tenth of the SURB lifetime (Mix Key
    # Rotation spec §7).
    purgeInterval = min(purgeInterval, ring.config.surbLifetime div 10)

  let store =
    if surbStore.isNil:
      SurbStore.new(purgeInterval = purgeInterval)
    else:
      surbStore

  # Without a key ring, a SURB reply is only accepted while its replay tag is
  # still cached, so holding credentials longer than the tag TTL cannot buy
  # anything.
  doAssert store.ttl <= tagManager.tagTTL,
    "SURB credential TTL must not exceed the replay tag TTL"

  mixProto.mixNodeInfo = mixNodeInfo
  mixProto.hopBackoff = hopBackoff
  mixProto.hopDrainTimeout = HopStreamDrainTimeout
  mixProto.switch = switch
  mixProto.rng = switch.rng
  mixProto.nodePool = MixNodePool.new(switch.peerStore, hopAddressPolicy, maxRecordAge)
  mixProto.tagManager = tagManager
  mixProto.keyRing = keyRing
  mixProto.surbStore = store
  mixProto.deliveryHandlers = initTable[string, MixDeliveryHandler]()
  mixProto.destReadBehaviors = newTable[string, DestReadBehavior]()

  mixProto.spamProtection = spamProtection
  mixProto.delayStrategy = delayStrategy.valueOr:
    if spamProtection.isSome:
      DelayStrategy(SpamProtectionDelayStrategy.new(rng = switch.rng))
    else:
      DelayStrategy(ExponentialDelayStrategy.new(rng = switch.rng))

  mixProto.coverTraffic = coverTraffic
  if coverTraffic.isSome:
    let ct = coverTraffic.get()
    ct.setCoverPacketBuilder(
      proc(
          epoch: uint64
      ): Future[Result[CoverPacketBuild, string]] {.async: (raises: [CancelledError]).} =
        return await mixProto.buildCoverPacket(epoch)
    )
    ct.setCoverProofGenerator(
      proc(
          packet: seq[byte], epoch: uint64
      ): Future[Result[CoverProofResult, string]] {.async: (raises: [CancelledError]).} =
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
    if spamProtection.isSome:
      let sp = spamProtection.get()
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
    # For now: sendWithSurb() takes `sink seq[byte]` and `move()`s into
    # buildMessage internally — the optimization stops at this boundary.
    (await mixProto.sendWithSurb(surb, message)).isOkOr:
      error "could not send reply", err = error

  mixProto.exitLayer =
    ExitLayer.init(switch, onReplyDialer, mixProto.destReadBehaviors, surbHoldTime)

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
    hopAddressPolicy: PeerAddressPolicy = defaultAddressPolicy,
    keyRing: Opt[MixKeyRing] = Opt.none(MixKeyRing),
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
    surbStore, hopBackoff, hopAddressPolicy, keyRing,
  )
  mixProto
