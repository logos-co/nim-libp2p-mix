# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import hashes, chronos, chronicles
import libp2p/stream/connection
from padding import DataSize

type MixExitConnection* = ref object of Connection
  message: seq[byte]
  response: seq[byte]

method readOnce*(
    self: MixExitConnection, pbytes: pointer, nbytes: int
): Future[int] {.async: (raises: [CancelledError, LPStreamError]).} =
  if self.message.len == 0:
    return 0 # Nothing else to read.
  let readLen = min(self.message.len, nbytes)
  copyMem(pbytes, addr self.message[0], readLen)
  self.message = self.message[readLen ..^ 1]
  self.activity = true
  readLen

method atEof*(self: MixExitConnection): bool =
  self.message.len == 0

method write*(
    self: MixExitConnection, msg: sink seq[byte]
): Future[void] {.async: (raises: [CancelledError, LPStreamError]).} =
  if msg.len() > DataSize:
    raise newException(LPStreamError, "exceeds max msg size of " & $DataSize & " bytes")
  self.response.add(msg)

func shortLog*(self: MixExitConnection): string {.raises: [].} =
  "MixExitConnection"

chronicles.formatIt(MixExitConnection):
  shortLog(it)

method initStream*(self: MixExitConnection) =
  discard

method closeImpl*(self: MixExitConnection): Future[void] {.async: (raises: []).} =
  discard

method getWrapped*(self: MixExitConnection): Connection =
  nil

func hash*(self: MixExitConnection): Hash =
  discard

proc getResponse*(self: MixExitConnection): seq[byte] =
  let r = self.response
  self.response = @[]
  return r

proc new*(T: typedesc[MixExitConnection], message: seq[byte]): T =
  T(message: message)
