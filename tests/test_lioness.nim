# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import nimcrypto, results
import libp2p_mix/[lioness, crypto]
from libp2p_mix/serialization import k, PayloadSize
import ./tools/[unittest]

proc seqBytes(n: int, start = 0): seq[byte] =
  ## Deterministic byte pattern. Built fresh on each call so callers get
  ## independent buffers (avoids the cursor-aliasing that `let copy = buf` can
  ## introduce when the buffer is later mutated in place via `var openArray`).
  var bytes = newSeq[byte](n)
  for i in 0 ..< n:
    bytes[i] = byte((start + i) and 0xff)
  bytes

suite "lioness_tests":
  test "round_trip_multiple_sizes":
    let lion = Lioness.init(MixLionessScheme, seqBytes(32)).expect("init")
    for size in [MinBlockSize, 512, PayloadSize]: # the actual Mix payload size
      var blk = seqBytes(size, 3)
      let expected = seqBytes(size, 3) # independent buffer, identical content
      check lion.encrypt(blk).isOk
      check blk != expected # ciphertext differs from plaintext
      check lion.decrypt(blk).isOk
      check blk == expected # round-trip recovers the plaintext

  test "determinism_same_seed_same_ciphertext":
    let lionA = Lioness.init(MixLionessScheme, seqBytes(32)).expect("init")
    let lionB = Lioness.init(MixLionessScheme, seqBytes(32)).expect("init")
    var a = seqBytes(128, 5)
    var b = seqBytes(128, 5)
    check lionA.encrypt(a).isOk
    check lionB.encrypt(b).isOk
    check a == b

  test "block_below_minimum_rejected":
    let lion = Lioness.init(MixLionessScheme, seqBytes(32)).expect("init")
    var tooSmall = newSeq[byte](MinBlockSize - 1)
    let encRes = lion.encrypt(tooSmall)
    let decRes = lion.decrypt(tooSmall)
    check:
      encRes.isErr and encRes.error == LionessError.BlockTooSmall
      decRes.isErr and decRes.error == LionessError.BlockTooSmall

  test "seed_below_kappa_rejected":
    let res = Lioness.init(MixLionessScheme, newSeq[byte](k - 1))
    check:
      res.isErr
      res.error == LionessError.InvalidSeed

  test "tamper_destroys_integrity_prefix":
    # LIONESS is a wide-block PRP: a single ciphertext bit flip scrambles the
    # whole plaintext, so the leading k zero bytes (the Sphinx integrity prefix)
    # no longer verify after decryption.
    let lion = Lioness.init(MixLionessScheme, seqBytes(32)).expect("init")
    var blk = newSeq[byte](256) # first k bytes are the zero integrity prefix
    check lion.encrypt(blk).isOk
    blk[100] = blk[100] xor 0x01
    check lion.decrypt(blk).isOk
    var prefixAllZero = true
    for i in 0 ..< k:
      if blk[i] != 0:
        prefixAllZero = false
    check not prefixAllZero

suite "lioness_known_answer_vectors":
  # Sub-primitive vectors, independently cross-checked against openssl (AES-CTR)
  # and python hashlib (SHA-256). Each expected value's exact reproduction
  # command is in the comment above its `check`.

  test "aes_ctr_stream_kat":
    # key = 00..1f (32B) -> k_aes = 00..0f, IV = 10..1f; data = 00..2f (48B).
    # Expected value reproduced with openssl AES-128-CTR:
    #   python3 -c "import sys; sys.stdout.buffer.write(bytes(range(48)))" |
    #   openssl enc -aes-128-ctr -K 000102030405060708090a0b0c0d0e0f \
    #     -iv 101112131415161718191a1b1c1d1e1f | xxd -p
    var data = seqBytes(48)
    aesCtrStream(seqBytes(32), data)
    check data ==
      fromHex(
        "07ffed77e5d005699807e41a82999c9c82d3d717cc1994155e60677997e4c017" &
          "ea001a4411c0de8c4dbfa0078df81355"
      )

  test "sha256_keyed_hash_kat":
    # SHA256(00..1f || "abc"). Expected value reproduced with python:
    #   python3 -c "import hashlib; print(hashlib.sha256(bytes(range(32)) + b'abc').hexdigest())"
    check sha256KeyedHash(seqBytes(32), @[byte 0x61, 0x62, 0x63]) ==
      fromHex("42fd4a8c529fdb402d577c701b291018f0b2c52207f96e2a057483fd349a9868")

  test "sha256_domsep_kdf_kat":
    # SHA256("payload_enc_key" || 00..1f). Expected value reproduced with python:
    #   python3 -c "import hashlib; print(hashlib.sha256(b'payload_enc_key' + bytes(range(32))).hexdigest())"
    check sha256DomSepKdf("payload_enc_key", seqBytes(32)) ==
      fromHex("8628ce30f82298838478ebd2744a6a31ef34a7d6a5a600b8e0c7de533510f85d")
