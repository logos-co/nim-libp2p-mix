# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import chronicles, results
import stew/[byteutils, leb128]
import libp2p/protobuf/minprotobuf
import libp2p/utils/sequninit

type
  MixReadMethod* = enum
    ReadExactly = 0
    ReadLp = 1
    ReadLine = 2

  MixReadSpec* = object
    readMethod*: MixReadMethod
    limit*: int
    sep*: string

  MixMessage* = object
    message*: seq[byte]
    codec*: string
    readSpec*: MixReadSpec

const DefaultMixReadSpec* = MixReadSpec(readMethod: ReadExactly, limit: 0, sep: "")

proc init*(
    T: typedesc[MixMessage],
    message: openArray[byte],
    codec: string,
    readSpec: MixReadSpec = DefaultMixReadSpec,
): T =
  return T(message: @message, codec: codec, readSpec: readSpec)

proc init*(
    T: typedesc[MixMessage],
    message: sink seq[byte],
    codec: string,
    readSpec: MixReadSpec = DefaultMixReadSpec,
): T =
  return T(message: move(message), codec: codec, readSpec: readSpec)

proc decodeLeb128[T: SomeUnsignedInt](
    data: openArray[byte], offset: int, field: string
): Result[tuple[value: T, len: int], string] =
  if offset >= data.len:
    return err("deserialization failed: missing " & field)

  let parsed = T.fromBytes(data[offset ..< min(data.len, offset + 10)], Leb128)
  if parsed.len == 0:
    return err("deserialization failed: incomplete " & field)
  if parsed.len < 0:
    return err("deserialization failed: invalid " & field)
  if Leb128.len(parsed.val) != parsed.len:
    return err("deserialization failed: overlong " & field)

  ok((parsed.val, parsed.len.int))

proc serialize*(mixMsg: MixMessage): seq[byte] =
  let
    codecBytes = mixMsg.codec.toBytes()
    codecLenBytes = toBytes(codecBytes.len.uint64, Leb128)
    limitBytes = toBytes(mixMsg.readSpec.limit.uint64, Leb128)
    sepBytes = mixMsg.readSpec.sep.toBytes()
    sepLenBytes = toBytes(sepBytes.len.uint64, Leb128)

  doAssert codecLenBytes.len <= 2, "serialization failed: codec length exceeds 2 bytes"
  doAssert mixMsg.readSpec.limit >= 0, "serialization failed: read limit is negative"

  let
    codecStart = codecLenBytes.len
    codecEnd = codecStart + codecBytes.len
    methodStart = codecEnd
    limitStart = methodStart + 1
    sepLenStart = limitStart + limitBytes.len
    sepStart = sepLenStart + sepLenBytes.len
    messageStart = sepStart + sepBytes.len

  var buf = newSeqUninit[byte](messageStart + mixMsg.message.len)
  buf[0 ..< codecLenBytes.len] = codecLenBytes.toOpenArray()
  buf[codecStart ..< codecEnd] = codecBytes
  buf[methodStart] = mixMsg.readSpec.readMethod.uint8
  buf[limitStart ..< sepLenStart] = limitBytes.toOpenArray()
  buf[sepLenStart ..< sepStart] = sepLenBytes.toOpenArray()
  buf[sepStart ..< messageStart] = sepBytes
  buf[messageStart ..< buf.len] = mixMsg.message
  buf

proc deserialize*(
    T: typedesc[MixMessage], data: openArray[byte]
): Result[MixMessage, string] =
  if data.len == 0:
    return err("deserialization failed: data is empty")

  let parsedCodecLen = ?decodeLeb128[uint16](data, 0, "codec length")
  let
    codecLen = parsedCodecLen.value.int
    codecStart = parsedCodecLen.len
    codecEnd = codecStart + codecLen

  if data.len < codecEnd:
    return err("deserialization failed: not enough data")

  if data.len <= codecEnd:
    return err("deserialization failed: missing read method")

  let methodByte = data[codecEnd]
  if methodByte > MixReadMethod.high.uint8:
    return err("deserialization failed: invalid read method")

  let parsedLimit = ?decodeLeb128[uint64](data, codecEnd + 1, "read limit")
  if parsedLimit.value > int.high.uint64:
    return err("deserialization failed: read limit too large")

  let sepLenOffset = codecEnd + 1 + parsedLimit.len
  let parsedSepLen = ?decodeLeb128[uint64](data, sepLenOffset, "read separator length")
  if parsedSepLen.value > int.high.uint64:
    return err("deserialization failed: read separator length too large")

  let
    sepLen = parsedSepLen.value.int
    sepStart = sepLenOffset + parsedSepLen.len
    sepEnd = sepStart + sepLen

  if data.len < sepEnd:
    return err("deserialization failed: not enough data")

  ok(
    T(
      codec: string.fromBytes(data[codecStart ..< codecEnd]),
      readSpec: MixReadSpec(
        readMethod: MixReadMethod(methodByte),
        limit: parsedLimit.value.int,
        sep: string.fromBytes(data[sepStart ..< sepEnd]),
      ),
      message: data[sepEnd ..< data.len],
    )
  )
