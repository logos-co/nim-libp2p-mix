# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import results
import libp2p/crypto/[crypto, curve25519]

const FieldElementSize* = Curve25519KeySize

func curve25519FieldPrime(): array[FieldElementSize, byte] =
  # This is calculated at compile time

  ## p = 2^255 - 19, encoded as a little-endian field element.
  var prime: array[FieldElementSize, byte]
  prime[FieldElementSize - 1] = 0x80
  # Start from 2^255, then subtract 19 with borrow across the little-endian bytes.

  var subtrahend = 19
  for i in 0 ..< FieldElementSize:
    let v = int(prime[i]) - subtrahend
    if v < 0:
      prime[i] = byte(v + 256)
      subtrahend = 1
    else:
      prime[i] = byte(v)
      subtrahend = 0
  prime

const Curve25519FieldPrime = curve25519FieldPrime()

type FieldElement* = Curve25519Key

func isZeroFieldElement*(bytes: openArray[byte]): bool =
  for b in bytes:
    if b != 0:
      return false
  true

func isCanonicalFieldElement(bytes: openArray[byte]): bool =
  ## Curve25519 public values are little-endian field elements modulo p = 2^255 - 19.
  if bytes.len != FieldElementSize:
    return false

  # Canonicality is numeric, so compare from the most significant little-endian byte.
  for i in countdown(FieldElementSize - 1, 0):
    if bytes[i] < Curve25519FieldPrime[i]:
      return true
    if bytes[i] > Curve25519FieldPrime[i]:
      return false
  false

proc bytesToFieldElement*(bytes: openArray[byte]): Result[FieldElement, string] =
  ## Convert bytes to FieldElement
  if bytes.len != FieldElementSize:
    return err("Field element size must be " & $FieldElementSize & " bytes")
  ok(intoCurve25519Key(bytes))

proc bytesToAlphaFieldElement*(bytes: openArray[byte]): Result[FieldElement, string] =
  ## Convert bytes to a Sphinx alpha field element.
  if bytes.len != FieldElementSize:
    return err("Field element size must be " & $FieldElementSize & " bytes")
  # Alpha is a public Curve25519 input, not replay-tag material: replay is keyed
  # on H(s) per spec Section 8.6.1 (see PR #18). Reject the all-zero encoding (a
  # low-order point that forces a zero shared secret) and any non-canonical
  # encoding, so malformed headers are dropped deterministically before use.
  if bytes.isZeroFieldElement():
    return err("Field element must not be all zero")
  if not bytes.isCanonicalFieldElement():
    return err("Field element must be canonical")
  ok(intoCurve25519Key(bytes))

proc fieldElementToBytes*(fe: FieldElement): seq[byte] =
  ## Convert FieldElement to bytes
  fe.getBytes()

# Generate a random FieldElement
proc generateRandomFieldElement*(): Result[FieldElement, string] =
  let rng = newRng()
  if rng.isNil:
    return err("Failed to create Rng with system randomness")
  ok(Curve25519Key.random(rng))

# Generate a key pair (private key and public key are both FieldElements)
proc generateKeyPair*(): Result[tuple[privateKey, publicKey: FieldElement], string] =
  let privateKey = generateRandomFieldElement().valueOr:
    return err("Error in private key generation: " & error)

  let publicKey = public(privateKey)
  ok((privateKey, publicKey))

proc multiplyPointWithScalars*(
    point: FieldElement, scalars: openArray[FieldElement]
): FieldElement =
  ## Multiply a given Curve25519 point with a set of scalars
  var res = point
  for scalar in scalars:
    Curve25519.mul(res, scalar)
  res

proc multiplyBasePointWithScalars*(
    scalars: openArray[FieldElement]
): Result[FieldElement, string] =
  ## Multiply the Curve25519 base point with a set of scalars
  if scalars.len <= 0:
    return err("Atleast one scalar must be provided")
  var res: FieldElement = public(scalars[0]) # Use the predefined base point
  for i in 1 ..< scalars.len:
    Curve25519.mul(res, scalars[i]) # Multiply with each scalar
  ok(res)
