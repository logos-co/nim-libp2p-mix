# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronicles, results
import stew/[byteutils, leb128]
import libp2p/protobuf/minprotobuf

type MixMessage* = object
  message*: seq[byte]
  codec*: string

proc init*(T: typedesc[MixMessage], message: openArray[byte], codec: string): T =
  return T(message: @message, codec: codec)

proc init*(T: typedesc[MixMessage], message: sink seq[byte], codec: string): T =
  return T(message: move(message), codec: codec)

proc serialize*(mixMsg: MixMessage): seq[byte] =
  let vbytes = toBytes(mixMsg.codec.len.uint64, Leb128)
  doAssert vbytes.len <= 2, "serialization failed: codec length exceeds 2 bytes"

  var buf = newSeqUninit[byte](vbytes.len + mixMsg.codec.len + mixMsg.message.len)
  buf[0 ..< vbytes.len] = vbytes.toOpenArray()
  buf[vbytes.len ..< vbytes.len + mixMsg.codec.len] = mixMsg.codec.toBytes()
  buf[vbytes.len + mixMsg.codec.len ..< buf.len] = mixMsg.message
  buf

proc deserialize*(
    T: typedesc[MixMessage], data: openArray[byte]
): Result[MixMessage, string] {.raises: [].} =
  if data.len == 0:
    return err("deserialization failed: data is empty")

  let parsed = uint16.fromBytes(data.toOpenArray(0, min(data.len, 2) - 1), Leb128)
  if parsed.len <= 0 or parsed.len != Leb128.len(parsed.val):
    return err("deserialization failed: invalid codec length")

  let
    varintLen = parsed.len.int
    codecLen = parsed.val.int

  if data.len < varintLen + codecLen:
    return err("deserialization failed: not enough data")

  ok(
    T(
      codec: string.fromBytes(data[varintLen ..< varintLen + codecLen]),
      message: data[varintLen + codecLen ..< data.len],
    )
  )
