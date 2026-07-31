# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results
import libp2p_mix/serialization
import libp2p_mix/padding
import ./tools/[unittest]

suite "Padding":
  test "padded output is always MessageSize bytes":
    for len in [0, 1, 13, DataSize - 1, DataSize]:
      let padded = addPadding(newSeq[byte](len)).expect("Pad error")
      check padded.len == MessageSize

  test "round trip preserves message bytes":
    let message =
      cast[seq[byte]]("This is a test message that survives padding and unpadding.")
    let padded = addPadding(message).expect("Pad error")

    check removePadding(padded).expect("Unpad error") == message

  test "padding length is encoded big endian in the first two bytes":
    # Wire layout is pinned here with literals rather than the module's own
    # constants, so a change to those constants shows up as a test failure.
    let
      message = cast[seq[byte]]("Hello, World!")
      padded = addPadding(message).expect("Pad error")
      encoded = (uint16(padded[0]) shl 8) or uint16(padded[1])

    check:
      encoded == uint16(DataSize - message.len)
      padded[2 ..< 2 + int(encoded)] == newSeq[byte](int(encoded))

  test "message size equal to DataSize needs no padding":
    let
      message = newSeq[byte](DataSize)
      padded = addPadding(message).expect("Pad error")

    check:
      padded[0] == 0
      padded[1] == 0
      removePadding(padded).expect("Unpad error") == message

  test "empty message is all padding":
    let padded = addPadding(newSeq[byte](0)).expect("Pad error")

    check:
      ((uint16(padded[0]) shl 8) or uint16(padded[1])) == uint16(DataSize)
      removePadding(padded).expect("Unpad error").len == 0

  test "addPadding rejects oversized message":
    let res = addPadding(newSeq[byte](DataSize + 1))
    check:
      res.isErr()
      res.error == "Message must be at most " & $DataSize & " bytes"

  test "removePadding rejects wrong length":
    let res = removePadding(newSeq[byte](MessageSize - 1))
    check:
      res.isErr()
      res.error == "Data must be exactly " & $MessageSize & " bytes"

  test "removePadding rejects out-of-range padding length":
    var padded = newSeq[byte](MessageSize)
    let bogus = uint16(DataSize + 1)
    padded[0] = byte(bogus shr 8)
    padded[1] = byte(bogus and 0xFF)

    let res = removePadding(padded)
    check:
      res.isErr()
      res.error == "Invalid padding length"
