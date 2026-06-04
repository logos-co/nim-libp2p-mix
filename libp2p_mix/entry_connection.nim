# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import hashes, chronos, results, chronicles
import libp2p/stream/connection
import libp2p/varint
import libp2p/utils/sequninit
import ./[mix_message, mix_protocol]
from fragmentation import DataSize

const DefaultSurbs = uint8(4)

type MixDialer* = proc(
  msg: sink seq[byte], codec: string, destination: MixDestination, readSpec: MixReadSpec
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).}

type MixParameters* = object
  expectReply*: Opt[bool]
  numSurbs*: Opt[uint8]
  readSpec*: Opt[MixReadSpec]

type MixEntryConnection* = ref object of Connection
  destination: MixDestination
  codec: string
  mixDialer: MixDialer
  params: MixParameters
  incoming: AsyncQueue[seq[byte]]
  incomingFut: Future[void]
  replyReceivedFut: Future[void]
  cached: seq[byte]

func shortLog*(conn: MixEntryConnection): string =
  if conn == nil:
    "MixEntryConnection(nil)"
  else:
    "MixEntryConnection(" & $conn.destination & ")"

chronicles.formatIt(MixEntryConnection):
  shortLog(it)

method readOnce*(
    s: MixEntryConnection, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  if s.isEof:
    raise newLPStreamEOFError()

  # Only wait for reply if cache is empty
  if s.cached.len == 0:
    if s.replyReceivedFut.isNil:
      raise newException(LPStreamError, "mix connection does not expect replies")
    try:
      await s.replyReceivedFut
      if s.cached.len == 0:
        # No data received - this is EOF
        s.isEof = true
        raise newLPStreamEOFError()
    except CancelledError as exc:
      raise exc
    except LPStreamEOFError as exc:
      raise exc
    except CatchableError as exc:
      raise (ref LPStreamError)(msg: "error in readOnce: " & exc.msg, parent: exc)

  # We have data in cache, return what we can
  let toRead = min(nbytes, s.cached.len)
  copyMem(pbytes, addr s.cached[0], toRead)
  s.cached = s.cached[toRead ..^ 1]

  return toRead

method write*(
    self: MixEntryConnection, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
  if msg.len() > DataSize:
    raise newException(LPStreamError, "exceeds max msg size of " & $DataSize & " bytes")
  await self.mixDialer(
    move(msg), self.codec, self.destination, self.params.readSpec.get(DefaultMixReadSpec)
  )

proc shortLog*(self: MixEntryConnection): string {.raises: [].} =
  "[MixEntryConnection] Destination: " & $self.destination

method closeImpl*(self: MixEntryConnection): Future[void] {.async: (raises: []).} =
  if not self.incomingFut.isNil:
    self.incomingFut.cancelSoon()

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
  instance.params = params

  if expectReply:
    instance.incoming = newAsyncQueue[seq[byte]]()
    instance.replyReceivedFut = newFuture[void]()
    let checkForIncoming = proc(): Future[void] {.async: (raises: [CancelledError]).} =
      instance.cached = await instance.incoming.get()
      instance.replyReceivedFut.complete()
    instance.incomingFut = checkForIncoming()

  instance.mixDialer = proc(
      msg: sink seq[byte], codec: string, dest: MixDestination, readSpec: MixReadSpec
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    let sendRes = await srcMix.anonymizeLocalProtocolSend(
      instance.incoming, move(msg), codec, dest, numSurbs, readSpec
    )
    if sendRes.isErr:
      raise newException(LPStreamError, sendRes.error)

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
  if params.expectReply.get(false) and destination.isForwardAddr and
      params.readSpec.isNone:
    return
      err("read spec is required when expecting replies from forwarded destinations")

  ok(MixEntryConnection.new(srcMix, destination, codec, params))
