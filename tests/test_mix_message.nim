# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, stew/byteutils
import libp2p_mix/[fragmentation, mix_message, mix_protocol, serialization]
import ./tools/[unittest]

# Define test cases
suite "mix_message_tests":
  test "serialize_and_deserialize_mix_message":
    let
      message = "Hello World!"
      codec = "/test/codec/1.0.0"
      mixMsg = MixMessage.init(message.toBytes(), codec)

    let serialized = mixMsg.serialize()
    let deserializedMsg =
      MixMessage.deserialize(serialized).expect("deserialization failed")

    check:
      message == string.fromBytes(deserializedMsg.message)
      codec == deserializedMsg.codec
      deserializedMsg.readSpec.readMethod == DefaultMixReadSpec.readMethod
      deserializedMsg.readSpec.limit == DefaultMixReadSpec.limit
      deserializedMsg.readSpec.sep == DefaultMixReadSpec.sep

  test "serialize_empty_mix_message":
    let
      emptyMessage = ""
      codec = "/test/codec/1.0.0"
      mixMsg = MixMessage.init(emptyMessage.toBytes(), codec)

    let serialized = mixMsg.serialize()
    let dMixMsg = MixMessage.deserialize(serialized).expect("deserialization failed")

    check:
      emptyMessage == string.fromBytes(dMixMsg.message)
      codec == dMixMsg.codec

  test "deserialize with empty data returns error":
    let res = MixMessage.deserialize(@[])
    check:
      res.isErr()
      res.error == "deserialization failed: data is empty"

  test "deserialize with invalid codec length returns error":
    # LEB128 overlong encoding of zero.
    let res = MixMessage.deserialize(@[0b10000000'u8, 0b00000000'u8])
    check:
      res.isErr()
      res.error == "deserialization failed: overlong codec length"

  test "deserialize with insufficient data returns error":
    # Varint says codec is 5 bytes, but only 1 byte follows
    let res = MixMessage.deserialize(@[0b00000101'u8, 0b00000000'u8])
    check:
      res.isErr()
      res.error == "deserialization failed: not enough data"

  test "serialize explicit ReadExactly layout":
    let mixMsg = MixMessage.init(
      "hello".toBytes(), "/ping", MixReadSpec(readMethod: ReadExactly, limit: 32)
    )

    check mixMsg.serialize() ==
      @[0x05'u8] & "/ping".toBytes() & @[0x00'u8, 0x20, 0x00] & "hello".toBytes()

  test "serialize codec length over one byte":
    var codecBytes = newSeq[byte](150)
    for i in 0 ..< codecBytes.len:
      codecBytes[i] = byte('a')

    let mixMsg = MixMessage.init(
      "hello".toBytes(),
      string.fromBytes(codecBytes),
      MixReadSpec(readMethod: ReadExactly, limit: 32),
    )

    check mixMsg.serialize() ==
      @[0x96'u8, 0x01] & codecBytes & @[0x00'u8, 0x20, 0x00] & "hello".toBytes()

  test "deserialize incomplete codec length returns error":
    let res = MixMessage.deserialize(@[0x96'u8])
    check:
      res.isErr()
      res.error == "deserialization failed: incomplete codec length"

  test "deserialize invalid read method returns error":
    let res =
      MixMessage.deserialize(@[0x05'u8] & "/ping".toBytes() & @[0x03'u8, 0x20, 0x00])
    check:
      res.isErr()
      res.error == "deserialization failed: invalid read method"

  test "serialize and deserialize ReadLine separator layout":
    let mixMsg = MixMessage.init(
      "hello".toBytes(),
      "/line",
      MixReadSpec(readMethod: ReadLine, limit: 1024, sep: "\r\n"),
    )

    let serialized = mixMsg.serialize()
    check serialized ==
      @[0x05'u8] & "/line".toBytes() & @[0x02'u8, 0x80, 0x08, 0x02] & "\r\n".toBytes() &
      "hello".toBytes()

    let deserializedMsg =
      MixMessage.deserialize(serialized).expect("deserialization failed")
    check:
      deserializedMsg.codec == "/line"
      deserializedMsg.message == "hello".toBytes()
      deserializedMsg.readSpec.readMethod == ReadLine
      deserializedMsg.readSpec.limit == 1024
      deserializedMsg.readSpec.sep == "\r\n"

  test "getMaxMessageSizeForCodec returns correct size":
    let codec = "/test/1.0.0"

    let size0 = getMaxMessageSizeForCodec(codec, 0)
    check:
      size0.get() > 0

    # Adding 1 SURB should reduce available size by a fixed amount (SurbSize)
    let size1 = getMaxMessageSizeForCodec(codec, 1)
    check:
      size1.get() < size0.get()
    let surbOverhead = size0.get() - size1.get()

    # Adding 2 SURBs should reduce by exactly double the per-SURB overhead
    let size2 = getMaxMessageSizeForCodec(codec, 2)
    check:
      size2.get() == size0.get() - 2 * surbOverhead

    # A longer codec should return a smaller max message size
    let longCodec = "/test/with/a/much/longer/codec/name/1.0.0"
    let sizeLong = getMaxMessageSizeForCodec(longCodec, 0)
    check:
      sizeLong.get() < size0.get()
      sizeLong.get() == size0.get() - (longCodec.len - codec.len)

  test "getMaxMessageSizeForCodec errors when overhead exceeds capacity":
    let codec = "/test/1.0.0"

    # Max SURBs that fit in payload:
    # (total size - codec overhead - SURB count byte) / SURB size
    let codecOverhead = MixMessage.init(@[], codec).serialize().len
    let maxSurbs = uint8((DataSize - codecOverhead - SurbLenSize) div SurbSize)
    check:
      getMaxMessageSizeForCodec(codec, maxSurbs).isOk
      getMaxMessageSizeForCodec(codec, maxSurbs + 1).isErr
