# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, sets]
import chronos
import libp2p_mix/[curve25519, key_rotation, tag_manager]
import ./tools/[unittest, crypto]

let start = Moment.init(1_000_000, Second)

proc makeTag(seed: byte): Tag =
  var tag: Tag
  for i in 0 ..< tag.len:
    tag[i] = byte((int(seed) * 32 + i) mod 256)
  tag

proc recordKeys(published: ref seq[FieldElement]): KeyHandler =
  return proc(publicKey: FieldElement) {.gcsafe, raises: [].} =
    published[].add(publicKey)

proc publicKeys(keys: seq[MixKey]): seq[FieldElement] =
  var publics: seq[FieldElement]
  for key in keys:
    publics.add(key.publicKey)
  publics

suite "Key Rotation Config":
  test "default config uses the recommended parameters":
    let config = KeyRotationConfig.init().expect("default config")
    check:
      config.rotationInterval == chronos.hours(1)
      config.graceWindow == chronos.minutes(90)
      config.acceptanceWindow == chronos.minutes(150)
      config.surbLifetime == chronos.minutes(15)
      config.surbHoldTime == chronos.minutes(13)

  test "init rejects timings that violate the constraints":
    check:
      # graceWindow <= rotationInterval + replacedRecordLifetime + 2 * maxTransit
      KeyRotationConfig.init(graceWindow = chronos.minutes(77)).isErr
      KeyRotationConfig.init(rotationInterval = ZeroDuration).isErr
      KeyRotationConfig.init(replacedRecordLifetime = chronos.seconds(-1)).isErr
      KeyRotationConfig.init(maxTransit = chronos.seconds(-1)).isErr

  test "init accepts a grace window just above the bound":
    check KeyRotationConfig.init(graceWindow = chronos.minutes(77) + 1.nanoseconds).isOk

suite "Mix Key Ring":
  var
    config: KeyRotationConfig
    ring: MixKeyRing
    published: ref seq[FieldElement]

  setup:
    config = KeyRotationConfig.init().expect("default config")
    ring = MixKeyRing.new(config, rng(), replayTableCapacity = 16)
    published = new seq[FieldElement]
    ring.setKeyHandler(recordKeys(published))

  template rotations(n: int): Moment =
    start + config.rotationInterval * n

  test "the first update generates and publishes a key":
    check ring.currentPublicKey().isNone

    ring.update(start)
    check:
      ring.len == 1
      published[] == @[ring.currentPublicKey().get()]

  test "the current key is replaced once the rotation interval passes":
    ring.update(start)
    let first = ring.candidates(start)[0]

    ring.update(rotations(1) - 1.nanoseconds)
    check published[].len == 1

    ring.update(rotations(1))
    check:
      published[].len == 2
      published[][1] == ring.currentPublicKey().get()
      ring.candidates(rotations(1))[1] == first

  test "an old key is accepted for the grace window, then destroyed":
    ring.update(start)
    let first = ring.candidates(start)[0]
    ring.update(rotations(1))

    let expiry = rotations(1) + config.graceWindow
    check:
      first in ring.candidates(expiry - 1.nanoseconds)
      first notin ring.candidates(expiry)
      not first.isAccepted(expiry)

    ring.update(expiry)
    check:
      first.isDestroyed
      ring.len == 2

  test "keys are tried from the current key to the old keys, newest first":
    for n in 0 .. 2:
      ring.update(rotations(n))

    # With the default 1 hour interval and 1 hour 30 minutes grace window, the
    # keys generated at 0:00, 1:00, and 2:00 are all accepted until 2:30.
    check:
      ring.candidates(rotations(2)).publicKeys ==
        @[published[][2], published[][1], published[][0]]
      ring.candidates(rotations(2) + chronos.minutes(30)).publicKeys ==
        @[published[][2], published[][1]]

  test "at most ceil(G / U) + 1 keys are held":
    for n in 0 .. 10:
      ring.update(rotations(n))
      ring.update(rotations(n) + chronos.minutes(30))
      check ring.len <= 3

  test "keys are generated independently":
    for n in 0 .. 5:
      ring.update(rotations(n))
    check published[].toHashSet.len == 6

  test "a late update replaces the current key once and starts a new interval":
    ring.update(start)
    ring.update(rotations(3))
    check:
      published[].len == 2
      ring.len == 2

    ring.update(rotations(4) - 1.nanoseconds)
    check published[].len == 2

  test "a destroyed key refuses to multiply and empties its replay table":
    ring.update(start)
    let
      key = ring.candidates(start)[0]
      (_, alpha) = generateKeyPair().expect("generate keypair error")
    check:
      key.multiply(alpha).isOk
      key.addTag(makeTag(1)) == TagAdded

    ring.update(rotations(1))
    ring.update(rotations(1) + config.graceWindow)
    check:
      key.isDestroyed
      key.multiply(alpha).isErr
      key.tagCount == 0
      not key.isTagSeen(makeTag(1))
      key.addTag(makeTag(2)) == TagCacheFull

  test "a handler set after the first update receives the current key":
    let late = MixKeyRing.new(config, rng(), replayTableCapacity = 16)
    late.update(start)
    let received = new seq[FieldElement]
    late.setKeyHandler(recordKeys(received))
    check received[] == @[late.currentPublicKey().get()]

  asyncTest "stop destroys every key":
    ring.update(start)
    ring.update(rotations(1))
    let keys = ring.candidates(rotations(1))
    check keys.len == 2

    await ring.stop()
    check:
      keys.allIt(it.isDestroyed)
      ring.len == 0
      ring.currentPublicKey().isNone

  asyncTest "start rotates and destroys keys on its own":
    let fastRing = MixKeyRing.new(
      KeyRotationConfig
        .init(
          rotationInterval = 100.milliseconds,
          graceWindow = 150.milliseconds,
          replacedRecordLifetime = ZeroDuration,
          maxTransit = 10.milliseconds,
        )
        .expect("fast rotation config"),
      rng(),
      replayTableCapacity = 16,
    )
    fastRing.start()
    defer:
      await fastRing.stop()

    let first = fastRing.candidates()[0]
    checkUntilTimeout:
      first.isDestroyed
      fastRing.currentPublicKey() != Opt.some(first.publicKey)

suite "Replay Table":
  var key: MixKey

  setup:
    let ring = MixKeyRing.new(
      KeyRotationConfig.init().expect("default config"), rng(), replayTableCapacity = 2
    )
    ring.update(start)
    key = ring.candidates(start)[0]

  test "addTag stores each tag once":
    check:
      key.addTag(makeTag(1)) == TagAdded
      key.addTag(makeTag(1)) == TagAlreadyPresent
      key.tagCount == 1
      key.isTagSeen(makeTag(1))
      not key.isTagSeen(makeTag(2))

  test "a full replay table rejects new tags without evicting":
    check:
      key.addTag(makeTag(1)) == TagAdded
      key.addTag(makeTag(2)) == TagAdded
      key.isReplayTableFull
      key.addTag(makeTag(3)) == TagCacheFull
      key.addTag(makeTag(1)) == TagAlreadyPresent
      key.tagCount == 2
      key.isTagSeen(makeTag(1))
      key.isTagSeen(makeTag(2))
      not key.isTagSeen(makeTag(3))
