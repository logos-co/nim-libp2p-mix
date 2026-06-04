# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronicles, chronos, metrics, std/[enumerate, sequtils]
import libp2p/builders
import libp2p/stream/connection
import libp2p/varint
import libp2p/utils/sequninit
import stew/byteutils
import
  ./[
    mix_message, mix_metrics, reply_connection, serialization, multiaddr,
    exit_connection,
  ]

type OnReplyDialer* =
  proc(surb: SURB, message: seq[byte]) {.async: (raises: [CancelledError]).}

type ExitLayer* = object
  switch: Switch
  onReplyDialer: OnReplyDialer

proc init*(T: typedesc[ExitLayer], switch: Switch, onReplyDialer: OnReplyDialer): T =
  ExitLayer(switch: switch, onReplyDialer: onReplyDialer)

proc replyDialerCbFactory(self: ExitLayer): MixReplyDialer =
  return proc(
      surbs: seq[SURB], msg: sink seq[byte]
  ): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
    let respFuts = surbs.mapIt(self.onReplyDialer(it, msg))
    await allFutures(respFuts)

proc reply(
    self: ExitLayer, surbs: seq[SURB], response: seq[byte]
) {.async: (raises: [CancelledError]).} =
  if surbs.len == 0:
    return

  let replyConn = MixReplyConnection.new(surbs, self.replyDialerCbFactory())
  defer:
    await replyConn.close()
  try:
    await replyConn.write(response)
  except LPStreamError as exc:
    error "could not reply", description = exc.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "REPLY_FAILED"])

proc runHandler(
    self: ExitLayer, codec: string, message: seq[byte], surbs: seq[SURB]
) {.async: (raises: [CancelledError]).} =
  let exitConn = MixExitConnection.new(message)
  defer:
    await exitConn.close()

  var hasHandler: bool = false
  for index, handler in enumerate(self.switch.ms.handlers):
    if codec in handler.protos:
      try:
        hasHandler = true
        await handler.protocol.handler(exitConn, codec)
      except CatchableError as e:
        error "Error during execution of MixProtocol handler: ", err = e.msg

  if not hasHandler:
    error "Handler doesn't exist", codec = codec
    return

  if surbs.len != 0:
    let response = exitConn.getResponse()
    await self.reply(surbs, response)

proc fwdRequest(
    self: ExitLayer,
    codec: string,
    readSpec: MixReadSpec,
    message: seq[byte],
    destination: Hop,
    surbs: seq[SURB],
) {.async: (raises: [CancelledError]).} =
  # If dialing destination fails, no response is returned to
  # the sender, so, flow can just end here. Only log errors
  # for now
  # https://github.com/vacp2p/mix/issues/86

  if destination == Hop():
    error "no destination available"
    mix_messages_error.inc(labelValues = ["Exit", "NO_DESTINATION"])
    return

  let (destPeerId, destAddr) = destination.get().bytesToMultiAddr().valueOr:
      error "Failed to convert bytes to multiaddress", err = error
      mix_messages_error.inc(labelValues = ["Exit", "INVALID_DEST"])
      return

  var response: seq[byte]
  try:
    let destConn = await self.switch.dial(destPeerId, @[destAddr], codec)
    defer:
      await destConn.close()
    await destConn.write(message)

    if surbs.len != 0:
      case readSpec.readMethod
      of ReadExactly:
        response = newSeqUninit[byte](readSpec.limit)
        if readSpec.limit > 0:
          await destConn.readExactly(addr response[0], readSpec.limit)
      of ReadLp:
        let rawResponse = await destConn.readLp(readSpec.limit)
        let vbytes = PB.toBytes(rawResponse.len.uint64)
        response = newSeqUninit[byte](rawResponse.len + vbytes.len)
        response[0 ..< vbytes.len] = vbytes.toOpenArray()
        response[vbytes.len ..< response.len] = rawResponse
      of ReadLine:
        if readSpec.sep.len == 0:
          error "ReadLine requires a separator", codec
          return
        let line = await destConn.readLine(readSpec.limit, readSpec.sep)
        response = line.toBytes() & readSpec.sep.toBytes()
  except LPStreamError as exc:
    error "Stream error while writing to next hop: ", err = exc.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "LPSTREAM_ERR"])
  except DialFailedError as exc:
    error "Failed to dial next hop: ", err = exc.msg
    mix_messages_error.inc(labelValues = ["ExitLayer", "DIAL_FAILED"])
  except CancelledError as exc:
    raise exc

  await self.reply(surbs, response)

proc onMessage*(
    self: ExitLayer,
    codec: string,
    readSpec: MixReadSpec,
    message: seq[byte],
    destination: Hop,
    surbs: seq[SURB],
) {.async: (raises: [CancelledError]).} =
  if destination == Hop():
    trace "onMessage - exit is destination", codec, message
    await self.runHandler(codec, message, surbs)
  else:
    trace "onMessage - exit is not destination", codec, message
    await self.fwdRequest(codec, readSpec, message, destination, surbs)
