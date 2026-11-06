# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/strutils
import chronos, metrics, results, stew/byteutils
import libp2p/peerid
import
  libp2p_mix/[padding, mix_message, mix_protocol, mix_node, serialization, mix_metrics]
import ./tools/[unittest, crypto]
import ./utils

proc entryErrors(reason: string): float64 =
  ## The count of entry errors with `reason`. 0 before the label exists.
  try:
    mix_messages_error.value(["Entry", reason])
  except KeyError:
    0.0

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

  test "round trips one- and two-byte codec lengths":
    let message = @[1.byte, 2, 3]

    for codecLen in [0, 1, 127, 128, 16_383]:
      let
        codec = repeat('a', codecLen)
        serialized = MixMessage.init(message, codec).serialize()
        deserialized =
          MixMessage.deserialize(serialized).expect("deserialization failed")

      check:
        deserialized.codec == codec
        deserialized.message == message

  test "serializedLen matches serialize across the varint boundary":
    for codecLen in [0, 1, 127, 128, 16_383]:
      let codec = repeat('a', codecLen)
      for message in [newSeq[byte](), @[1.byte, 2, 3]]:
        check serializedLen(codec, message.len) ==
          MixMessage.init(message, codec).serialize().len
    # A codec of 16384 bytes needs a three byte length prefix. The size check
    # returns an error and does not serialize the codec.
    check getMaxMessageSizeForCodec(repeat('a', 16_384)).isErr

  test "deserialize with empty data returns error":
    let res = MixMessage.deserialize(@[])
    check:
      res.isErr()
      res.error == "deserialization failed: data is empty"

  test "deserialize with invalid codec length returns error":
    # LEB128 continuation bit set — incomplete varint
    for prefix in [
      @[0b10000000'u8],
      @[0b10000000'u8, 0b00000000],
      @[0b10000000'u8, 0b10000000, 0b00000001],
    ]:
      let res = MixMessage.deserialize(prefix)
      check:
        res.isErr()
        res.error == "deserialization failed: invalid codec length"

  test "deserialize with insufficient data returns error":
    # Varint says codec is 5 bytes, but only 1 byte follows
    let res = MixMessage.deserialize(@[0b00000101'u8, 0b00000000'u8])
    check:
      res.isErr()
      res.error == "deserialization failed: not enough data"

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

  test "the public sends fail while the protocol is not running":
    let info = MixNodeInfo.generateRandom(0, rng())
    let mix =
      MixProtocol.new(info, createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey)))
    let other = MixNodeInfo.generateRandom(0, rng())

    proc failures(): seq[string] =
      let sent = waitFor mix.anonymizeLocalProtocolSend(
        newAsyncQueue[seq[byte]](),
        @[1.byte],
        "/test/1.0.0",
        MixDestination.init(other.peerId, other.multiAddr),
        0,
      )
      let reply = waitFor mix.sendSurbReply(default(SURB), @[1.byte])
      let cover = waitFor mix.sendCoverPacket(other.peerId, other.multiAddr, @[1.byte])
      @[sent.error(), reply.error(), cover.error()]

    let notRunning = @[
      "anonymizeLocalProtocolSend: mix protocol is not running",
      "sendSurbReply: mix protocol is not running",
      "sendCoverPacket: mix protocol is not running",
    ]
    check failures() == notRunning

    waitFor mix.start()
    waitFor mix.stop()
    check failures() == notRunning

  test "a send larger than the capacity fails before any peer selection":
    # The pool is empty, so a peer selection would fail with its own error.
    let info = MixNodeInfo.generateRandom(0, rng())
    let mix =
      MixProtocol.new(info, createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey)))
    waitFor mix.start()
    defer:
      waitFor mix.stop()
    let codec = "/test/1.0.0"
    let capacity = getMaxMessageSizeForCodec(codec, 1).get()
    let before = entryErrors("INVALID_SIZE")
    let other = MixNodeInfo.generateRandom(0, rng())
    let sent = waitFor mix.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      newSeq[byte](capacity + 1),
      codec,
      MixDestination.init(other.peerId, other.multiAddr),
      1,
    )
    check:
      sent.isErr
      sent.error.startsWith("message exceeds the codec and reply payload capacity")
      entryErrors("INVALID_SIZE") == before + 1

  test "a send of exactly the capacity with a reply passes the size check":
    # The pool is empty, so a send that passes the size check fails at the peer
    # selection with LOW_MIX_POOL.
    let info = MixNodeInfo.generateRandom(0, rng())
    let mix =
      MixProtocol.new(info, createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey)))
    waitFor mix.start()
    defer:
      waitFor mix.stop()
    let codec = "/test/1.0.0"
    let capacity = getMaxMessageSizeForCodec(codec, 1).get()
    let invalidBefore = entryErrors("INVALID_SIZE")
    let lowPoolBefore = entryErrors("LOW_MIX_POOL")
    let other = MixNodeInfo.generateRandom(0, rng())
    let sent = waitFor mix.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      newSeq[byte](capacity),
      codec,
      MixDestination.init(other.peerId, other.multiAddr),
      1,
    )
    check:
      sent.isErr
      sent.error.startsWith("No. of public mix nodes")
      entryErrors("INVALID_SIZE") == invalidBefore
      entryErrors("LOW_MIX_POOL") == lowPoolBefore + 1

  test "a codec that leaves no capacity fails and counts INVALID_SIZE":
    let info = MixNodeInfo.generateRandom(0, rng())
    let mix =
      MixProtocol.new(info, createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey)))
    waitFor mix.start()
    defer:
      waitFor mix.stop()
    let codec = "/" & 'x'.repeat(DataSize)
    check getMaxMessageSizeForCodec(codec).isErr
    let before = entryErrors("INVALID_SIZE")
    let other = MixNodeInfo.generateRandom(0, rng())
    let sent = waitFor mix.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      @[1.byte],
      codec,
      MixDestination.init(other.peerId, other.multiAddr),
      0,
    )
    check:
      sent.isErr
      entryErrors("INVALID_SIZE") == before + 1
