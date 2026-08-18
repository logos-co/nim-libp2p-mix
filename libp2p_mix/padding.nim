# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import ./serialization
import results, stew/endians2

const PaddingLengthSize = 2
const DataSize* = MessageSize - PaddingLengthSize

# Padding keeps every Sphinx payload the same size so packets stay
# indistinguishable on the wire. Splitting and reassembling oversized messages
# is the origin protocol's or application's responsibility, per LIBP2P-MIX
# section 8.3.3; the Mix Protocol only handles messages that fit in one packet.
#
# Wire layout, MessageSize bytes total:
#
#   +------------------------+-------------------+-----------+
#   | paddingLength (2 bytes) | zero padding      | message   |
#   +------------------------+-------------------+-----------+

proc addPadding*(messageBytes: openArray[byte]): Result[seq[byte], string] =
  ## Prefix `messageBytes` with its padding length and enough zero bytes to
  ## reach exactly MessageSize.
  if messageBytes.len > DataSize:
    return err("Message must be at most " & $DataSize & " bytes")

  let paddingLength = uint16(DataSize - messageBytes.len)
  ok(@(paddingLength.toBytesBE()) & newSeq[byte](int(paddingLength)) & @messageBytes)

proc removePadding*(padded: openArray[byte]): Result[seq[byte], string] =
  ## Recover the message written by `addPadding`.
  if padded.len != MessageSize:
    return err("Data must be exactly " & $MessageSize & " bytes")

  let paddingLength = int(uint16.fromBytesBE(padded[0 .. PaddingLengthSize - 1]))
  if paddingLength > DataSize:
    return err("Invalid padding length")

  ok(@(padded[PaddingLengthSize + paddingLength ..^ 1]))
