# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import hashes, chronos, results, chronicles, metrics
import libp2p/stream/connection
import libp2p/varint
import ./[mix_protocol, mix_metrics, surb_store]
from fragmentation import DataSize

const DefaultSurbs = uint8(4)

const DefaultReplyTimeout = chronos.seconds(30)
  ## How long `readOnce` waits for a mix reply before giving up.
  ##
  ## Roughly 75x the expected round trip (two delayed hops each way at the
  ## default 100ms mean) and comfortably above the worst case implied by the
  ## exponential delay tail, so it will not fire on a merely slow reply.

type MixDialer* = proc(
  msg: sink seq[byte], codec: string, destination: MixDestination
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).}

type MixParameters* = object
  expectReply*: Opt[bool]
  numSurbs*: Opt[uint8]
  replyTimeout*: Opt[Duration]
    ## `none` applies a default of 30 seconds. Pass
    ## `Opt.some(InfiniteDuration)` to wait indefinitely.

type MixEntryConnection* = ref object of Connection
  destination: MixDestination
  codec: string
  mixDialer: MixDialer
  params: MixParameters
  incoming: AsyncQueue[seq[byte]]
  incomingFut: Future[void]
  replyReceivedFut: Future[void]
  cached: seq[byte]
  replyTimeout: Duration
  sent: bool
  replySession: Opt[SurbSession]

func shortLog*(conn: MixEntryConnection): string =
  if conn == nil:
    "MixEntryConnection(nil)"
  else:
    "MixEntryConnection(" & $conn.destination & ")"

chronicles.formatIt(MixEntryConnection):
  shortLog(it)

proc releaseReplyCreds(self: MixEntryConnection) =
  ## Idempotent, so the timeout and close paths can both call it.
  self.replySession.withValue(session):
    session.release()
  self.replySession = Opt.none(SurbSession)

method readOnce*(
    s: MixEntryConnection, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  if s.isEof:
    raise newLPStreamEOFError()

  # Only wait for reply if cache is empty
  if s.cached.len == 0:
    if s.replyReceivedFut.isNil:
      raise newException(LPStreamError, "mix connection does not expect replies")

    var timedOut = false
    try:
      if s.replyTimeout == InfiniteDuration:
        await s.replyReceivedFut
      else:
        timedOut = not await s.replyReceivedFut.withTimeout(s.replyTimeout)
    except CancelledError as exc:
      raise exc
    except LPStreamEOFError as exc:
      raise exc
    except CatchableError as exc:
      raise (ref LPStreamError)(msg: "error in readOnce: " & exc.msg, parent: exc)

    # Raised outside the try so it is not rewrapped as a generic LPStreamError.
    if timedOut:
      # libp2p treats a timeout as end-of-stream rather than a distinct error
      # (its idle handler simply closes the connection), so surface plain EOF
      # and let protocols handle it exactly as they would a peer going away.
      # The metric is what carries the diagnostic signal.
      trace "No mix reply within timeout", s, timeout = s.replyTimeout
      mix_reply_timeouts.inc()
      s.isEof = true
      # Not deferred to close: the guarantee should not depend on the caller
      # remembering to close.
      s.releaseReplyCreds()
      if not s.incomingFut.isNil:
        s.incomingFut.cancelSoon()
      raise newLPStreamEOFError()

    if s.cached.len == 0:
      # No data received - this is EOF
      s.isEof = true
      raise newLPStreamEOFError()

  # We have data in cache, return what we can
  let toRead = min(nbytes, s.cached.len)
  copyMem(pbytes, addr s.cached[0], toRead)
  s.cached = s.cached[toRead ..^ 1]

  return toRead

method write*(
    self: MixEntryConnection, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
  ## A reply-expecting connection carries a single request/response exchange:
  ## there is one incoming queue and one reply future, so a second write would
  ## have its reply silently dropped. Reject it instead. Fire-and-forget
  ## connections have no such limit.
  if msg.len() > DataSize:
    raise newException(LPStreamError, "exceeds max msg size of " & $DataSize & " bytes")

  if not self.replyReceivedFut.isNil and self.sent:
    raise newException(
      LPStreamError,
      "mix connection expecting a reply supports a single write; " &
        "use one connection per request",
    )

  await self.mixDialer(move(msg), self.codec, self.destination)
  self.sent = true

proc shortLog*(self: MixEntryConnection): string {.raises: [].} =
  "[MixEntryConnection] Destination: " & $self.destination

method closeImpl*(self: MixEntryConnection): Future[void] {.async: (raises: []).} =
  self.releaseReplyCreds()
  if not self.incomingFut.isNil:
    self.incomingFut.cancelSoon()

method getWrapped*(self: MixEntryConnection): Connection =
  nil

func hash*(self: MixEntryConnection): Hash =
  hash($self.destination)

proc new*(
    T: typedesc[MixEntryConnection],
    srcMix: MixProtocol,
    destination: MixDestination,
    codec: string,
    params: MixParameters,
): T {.raises: [].} =
  let expectReply = params.expectReply.get(false)
  let numSurbs =
    if expectReply:
      params.numSurbs.get(DefaultSurbs)
    else:
      0

  var instance = T()
  instance.destination = destination
  instance.codec = codec
  instance.replyTimeout = params.replyTimeout.get(DefaultReplyTimeout)

  if expectReply:
    instance.incoming = newAsyncQueue[seq[byte]]()
    instance.replyReceivedFut = newFuture[void]()
    let checkForIncoming = proc(): Future[void] {.async: (raises: [CancelledError]).} =
      instance.cached = await instance.incoming.get()
      instance.replyReceivedFut.complete()
    instance.incomingFut = checkForIncoming()

  instance.mixDialer = proc(
      msg: sink seq[byte], codec: string, dest: MixDestination
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    let session = (
      await srcMix.anonymizeLocalProtocolSend(
        instance.incoming, move(msg), codec, dest, numSurbs
      )
    ).valueOr:
      raise newException(LPStreamError, error)

    # At most one: a reply-expecting connection accepts a single write, and a
    # fire-and-forget one never registers credentials.
    instance.replySession = session

  instance

proc toConnection*(
    srcMix: MixProtocol,
    destination: MixDestination,
    codec: string,
    params: MixParameters = MixParameters(),
): Result[Connection, string] {.gcsafe, raises: [].} =
  ## Create a stream to send and optionally receive responses.
  ## Under the hood it will wrap the message in a sphinx packet
  ## and send it via a random mix path.
  ##
  ## When `expectReply` is set the connection models one request/response
  ## exchange and accepts a single `write`; open a connection per request.
  ## `readOnce` waits up to `params.replyTimeout` for the reply, then reports
  ## end-of-stream as it would for any peer that went away.
  if not srcMix.hasDestReadBehavior(codec):
    if params.expectReply.get(false):
      return err("no destination read behavior for codec")
    else:
      warn "no destination read behavior for codec", codec

  ok(MixEntryConnection.new(srcMix, destination, codec, params))
