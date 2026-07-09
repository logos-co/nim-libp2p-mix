# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Generic LIONESS wide-block cipher (Anderson & Biham) for Sphinx payload
## encryption, per LIP-183 ("LIONESS encryption scheme for LIBP2P-MIX payload
## encryption").
##
## Spec: https://lip.logos.co/anoncomms/raw/mix-lioness.html
## Section references of the form `LIP-183 §N` in the LIONESS code point there.
##
## Layering
## --------
## - This module is the primitive INTERFACE plus the Feistel CORE. It contains
##   no cipher / hash / KDF algorithm of its own: it only calls through the
##   proc pointers held in a `LionessScheme`. (It imports `nimcrypto/utils`
##   solely for `burnMem` zeroization; no cipher or hash from nimcrypto is used
##   here.)
## - The concrete primitives (AES-CTR + SHA-256, per LIP-183 §4) and the
##   `MixLionessScheme` that binds them live in `crypto.nim`. Swapping the
##   crypto algorithms means adding a new `LionessScheme` there; this core does
##   not change.
##
## Construction (LIP-183 §5)
## ----------------------
## The block `B = L || R` splits into a mu-byte left half `L` and a right half
## `R` of size `|B| - mu`. Encryption applies four Feistel rounds:
##
##   R1 = R0 xor S(K1 xor L0)      (stream round, K1)
##   L1 = L0 xor H_K2(R1)          (hash round,   K2)
##   R2 = R1 xor S(K3 xor L1)      (stream round, K3)
##   L2 = L1 xor H_K4(R2)          (hash round,   K4)
##   C  = L2 || R2
##
## Decryption reverses the rounds. LIONESS provides no integrity on its own;
## the Sphinx layer prepends `kappa` zero bytes to the plaintext and verifies
## them after decryption to detect tampering.

{.push raises: [], gcsafe.}

import results
import nimcrypto/utils # burnMem only (secure zeroization); no cipher/hash used here
from ./serialization import k # kappa: the Mix security parameter (single source)

export results

const
  Mu* = 32
    ## mu: size of the left half `L`, the stream-cipher key, the keyed-hash key,
    ## and the hash digest. Fixed to 32 bytes by LIP-183.
  MinBlockSize* = 2 * Mu
    ## Minimum block size (64 bytes): guarantees `|L| = mu` and `|R| >= mu`.
  RoundKeyDomains = ["lioness_key1", "lioness_key2", "lioness_key3", "lioness_key4"]
    ## LIP-183 §5.3 domain separators for the four round keys (K1..K4).

# The minimum LIONESS seed length is the Mix security parameter kappa
# (`serialization.k`), per LIP-183 §5.3.

type
  Digest* = array[Mu, byte] ## A mu-byte key or hash output.

  LionessStream* = proc(key: openArray[byte], data: var openArray[byte]) {.
    nimcall, gcsafe, raises: []
  .} ## Stream cipher S: XOR keystream(key) into `data` in place. `key.len == Mu`.

  LionessHash* = proc(key, msg: openArray[byte]): Digest {.nimcall, gcsafe, raises: [].}
    ## Keyed hash H_k(m): mu-byte `key`, arbitrary `msg`, mu-byte digest.

  LionessKdf* =
    proc(dom: string, seed: openArray[byte]): Digest {.nimcall, gcsafe, raises: [].}
    ## Key-derivation function KDF(dom, seed) -> mu-byte key.

  LionessScheme* = object
    ## A concrete instantiation of the three LIONESS primitives. Swap primitives
    ## by constructing a different scheme (see `MixLionessScheme` in crypto.nim).
    stream*: LionessStream
    hash*: LionessHash
    kdf*: LionessKdf

  LionessError* {.pure.} = enum
    BlockTooSmall
    InvalidSeed

  Lioness* = object
    ## A stateless LIONESS instance: a scheme plus the four derived round keys.
    ## Call `clear` when done to wipe key material.
    scheme: LionessScheme
    k1, k2, k3, k4: Digest

proc clear*(self: var Lioness) =
  ## Zeroize the derived round keys.
  burnMem(self.k1)
  burnMem(self.k2)
  burnMem(self.k3)
  burnMem(self.k4)

proc init*(
    T: type Lioness, scheme: LionessScheme, seed: openArray[byte]
): Result[Lioness, LionessError] =
  ## Build a LIONESS instance by deriving the four round keys from `seed` via
  ## the scheme's KDF, using the four `lioness_keyN` domain separators
  ## (LIP-183 §5.3).
  ## `seed.len` must be at least `k` (kappa).
  if seed.len < k:
    return err(LionessError.InvalidSeed)
  var l = Lioness(scheme: scheme)
  l.k1 = scheme.kdf(RoundKeyDomains[0], seed) # K1, K3 -> stream rounds
  l.k2 = scheme.kdf(RoundKeyDomains[1], seed) # K2, K4 -> hash rounds
  l.k3 = scheme.kdf(RoundKeyDomains[2], seed)
  l.k4 = scheme.kdf(RoundKeyDomains[3], seed)
  ok(l)

proc streamRound(self: Lioness, blk: var openArray[byte], subkey: Digest) =
  ## R ^= S(subkey xor L)
  var roundKey: Digest
  for i in 0 ..< Mu:
    roundKey[i] = blk[i] xor subkey[i]
  self.scheme.stream(roundKey, blk.toOpenArray(Mu, blk.high))
  burnMem(roundKey)

proc hashRound(self: Lioness, blk: var openArray[byte], subkey: Digest) =
  ## L ^= H_subkey(R)
  var d = self.scheme.hash(subkey, blk.toOpenArray(Mu, blk.high))
  for i in 0 ..< Mu:
    blk[i] = blk[i] xor d[i]
  burnMem(d)

proc encrypt*(self: Lioness, blk: var openArray[byte]): Result[void, LionessError] =
  ## Encrypt one wide block in place (LIP-183 §5.4). `blk.len` >= `2 * Mu`.
  if blk.len < MinBlockSize:
    return err(LionessError.BlockTooSmall)
  self.streamRound(blk, self.k1)
  self.hashRound(blk, self.k2)
  self.streamRound(blk, self.k3)
  self.hashRound(blk, self.k4)
  ok()

proc decrypt*(self: Lioness, blk: var openArray[byte]): Result[void, LionessError] =
  ## Decrypt one wide block in place (LIP-183 §5.5). Inverse of `encrypt`.
  if blk.len < MinBlockSize:
    return err(LionessError.BlockTooSmall)
  self.hashRound(blk, self.k4)
  self.streamRound(blk, self.k3)
  self.hashRound(blk, self.k2)
  self.streamRound(blk, self.k1)
  ok()

{.pop.}
