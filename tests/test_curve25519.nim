# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results
import libp2p/[crypto/curve25519]
import libp2p_mix/curve25519
import ./tools/[unittest]

proc isNotZero(key: FieldElement): bool =
  for byte in key:
    if byte != 0:
      return true
  return false

suite "curve25519_tests":
  test "generate_key_pair":
    let (privateKey, publicKey) = generateKeyPair().expect("generate keypair error")

    check:
      fieldElementToBytes(privateKey).len == FieldElementSize
      fieldElementToBytes(publicKey).len == FieldElementSize
      privateKey.isNotZero()
      publicKey.isNotZero()

    let derivedPublicKey = multiplyBasePointWithScalars(@[privateKey]).expect(
        "multiply base point with scalar error"
      )

    check publicKey == derivedPublicKey

  test "alpha field element rejects invalid alpha encodings":
    check bytesToAlphaFieldElement(newSeq[byte](FieldElementSize)).isErr()

    var nonCanonical = newSeq[byte](FieldElementSize)
    nonCanonical[FieldElementSize - 1] = byte(0x80)
    check bytesToAlphaFieldElement(nonCanonical).isErr()

    let (_, publicKey) = generateKeyPair().expect("generate keypair error")
    check:
      bytesToAlphaFieldElement(fieldElementToBytes(publicKey)).isOk()
      not publicKey.isZeroFieldElement()

  test "commutativity":
    let
      x1 = generateRandomFieldElement().expect("generate random field element error")
      x2 = generateRandomFieldElement().expect("generate random field element error")
      res1 = multiplyBasePointWithScalars(@[x1, x2]).expect(
          "multiply base point with scalar errors"
        )
      res2 = multiplyBasePointWithScalars(@[x2, x1]).expect(
          "multiply base point with scalar errors"
        )
      res3 = multiplyPointWithScalars(public(x2), @[x1])
      res4 = multiplyPointWithScalars(public(x1), @[x2])

    check:
      res1 == res2
      res1 == res3
      res1 == res4
