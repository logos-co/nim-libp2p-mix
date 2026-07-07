# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import endians, nimcrypto
import ./lioness # LIONESS interface types (Digest, LionessScheme) for the Mix scheme

proc aes_ctr*(key, iv, data: openArray[byte]): seq[byte] =
  ## Processes 'data' using AES in CTR mode.
  ## For CTR mode, the same function handles both encryption and decryption.
  doAssert key.len == 16, "Key must be 16 bytes for AES-128"
  doAssert iv.len == 16, "IV must be 16 bytes for AES-128"

  var
    ctx: CTR[aes128]
    output = newSeq[byte](data.len)

  ctx.init(key, iv)
  ctx.encrypt(data, output)
  ctx.clear()

  output

proc advance_ctr*(iv: var openArray[byte], blocks: uint64) =
  ## Advances the counter in the AES-CTR IV by a specified number of blocks.
  var counter: uint64
  bigEndian64(addr counter, addr iv[8])
  counter += blocks
  bigEndian64(addr iv[8], addr counter)

proc aes_ctr_start_index*(key, iv, data: openArray[byte], startIndex: int): seq[byte] =
  ## Encrypts 'data' using AES in CTR mode from startIndex, without processing all preceding data.
  ## For CTR mode, the same function handles both encryption and decryption.
  doAssert key.len == 16, "Key must be 16 bytes for AES-128"
  doAssert iv.len == 16, "IV must be 16 bytes for AES-128"
  doAssert startIndex mod 16 == 0, "Start index must be a multiple of 16"

  var advIV = @iv

  # Advance the counter to the start index
  let blocksToAdvance = startIndex div 16
  advance_ctr(advIV, blocksToAdvance.uint64)

  return aes_ctr(key, advIV, data)

proc sha256_hash*(data: openArray[byte]): array[32, byte] =
  ## hashes 'data' using SHA-256.
  return sha256.digest(data).data

proc kdf*(key: openArray[byte]): seq[byte] =
  ## Returns the hash of 'key' truncated to 16 bytes.
  let hash = sha256_hash(key)
  return hash[0 .. 15]

proc hmac*(key, data: openArray[byte]): seq[byte] =
  ## Computes a HMAC for 'data' using given 'key'.
  let hmac = sha256.hmac(key, data).data
  return hmac[0 .. 15]

# ---------------------------------------------------------------------------
# LIONESS primitive instantiation (LIP-183 §4). These are the only
# place the LIONESS payload cipher touches a concrete crypto library; the
# `lioness.nim` core stays algorithm-agnostic. Swap the payload primitives by
# defining a different `LionessScheme`.
# ---------------------------------------------------------------------------

proc aesCtrStream*(
    key: openArray[byte], data: var openArray[byte]
) {.nimcall, gcsafe, raises: [].} =
  ## LIONESS stream cipher S (LIP-183 §4.1): the mu-byte round key is split as
  ## k_aes (first 16 bytes) || IV (last 16 bytes); the AES-CTR keystream is
  ## XORed into `data` in place.
  doAssert key.len == Mu, "LIONESS stream key must be Mu bytes"
  var ctx: CTR[aes128]
  ctx.init(key.toOpenArray(0, 15), key.toOpenArray(16, Mu - 1))
  ctx.encrypt(data, data)
  ctx.clear()

proc sha256KeyedHash*(
    key, msg: openArray[byte]
): Digest {.nimcall, gcsafe, raises: [].} =
  ## LIONESS keyed hash H_k (LIP-183 §4.2): SHA256(key || msg). Used only inside
  ## the LIONESS Feistel construction; it is NOT a general-purpose MAC.
  var ctx: sha256
  ctx.init()
  ctx.update(key)
  ctx.update(msg)
  let digest = ctx.finish().data
  ctx.clear()
  digest

proc sha256DomSepKdf*(
    dom: string, seed: openArray[byte]
): Digest {.nimcall, gcsafe, raises: [].} =
  ## LIONESS KDF (LIP-183 §4.3): SHA256(dom || seed), full 32-byte output.
  var ctx: sha256
  ctx.init()
  ctx.update(dom.toOpenArrayByte(0, dom.high))
  ctx.update(seed)
  let digest = ctx.finish().data
  ctx.clear()
  digest

const MixLionessScheme* =
  LionessScheme(stream: aesCtrStream, hash: sha256KeyedHash, kdf: sha256DomSepKdf)
  ## The LIP-183 payload-encryption scheme: AES-CTR + SHA-256.
