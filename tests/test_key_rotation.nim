# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/tables
from std/times import Time, toUnix, nanosecond, initTime
import chronos
import libp2p_mix/[curve25519, key_rotation, tag_manager]
import ./tools/[unittest, crypto]

const TestPeriod: KeyPeriod = 1000

proc timeAt(schedule: KeySchedule, period: KeyPeriod, offset: Duration): Time =
  ## Wall-clock time offset after the start of period.
  let start = schedule.periodStart(period)
  let ns = start.toUnix() * 1_000_000_000 + start.nanosecond + offset.nanoseconds
  initTime(ns div 1_000_000_000, ns mod 1_000_000_000)

proc makeTag(seed: byte): Tag =
  var tag: Tag
  for i in 0 ..< tag.len:
    tag[i] = byte((int(seed) * 32 + i) mod 256)
  tag

proc periods(keys: seq[MixKey]): seq[KeyPeriod] =
  var keyPeriods: seq[KeyPeriod]
  for key in keys:
    keyPeriods.add(key.period)
  keyPeriods

suite "Key Schedule":
  test "default schedule uses the recommended parameters":
    let schedule = KeySchedule.init().expect("default schedule")
    check:
      schedule.periodDuration == chronos.hours(3)
      schedule.earlyWindow == chronos.minutes(1)
      schedule.graceWindow == chronos.minutes(15)
      schedule.acceptanceWindow == chronos.hours(3) + chronos.minutes(16)

  test "init rejects windows that violate the constraints":
    check:
      # earlyWindow < 2 * maxClockOffset
      KeySchedule.init(earlyWindow = chronos.seconds(29)).isErr
      # graceWindow <= 2 * maxTransit + 2 * maxClockOffset
      KeySchedule.init(graceWindow = chronos.minutes(2) + chronos.seconds(30)).isErr
      # periodDuration <= earlyWindow + graceWindow
      KeySchedule.init(periodDuration = chronos.minutes(16)).isErr
      KeySchedule.init(maxClockOffset = chronos.seconds(-1)).isErr
      KeySchedule.init(maxTransit = chronos.seconds(-1)).isErr

  test "init accepts windows at the constraint boundaries":
    check:
      KeySchedule.init(earlyWindow = chronos.seconds(30)).isOk

      KeySchedule.init(
        graceWindow = chronos.minutes(2) + chronos.seconds(30) + 1.nanoseconds
      ).isOk
      KeySchedule.init(periodDuration = chronos.minutes(16) + 1.nanoseconds).isOk

  test "keyPeriod changes exactly at periodStart":
    let schedule = KeySchedule.init().expect("default schedule")
    check:
      schedule.keyPeriod(schedule.periodStart(TestPeriod)) == TestPeriod
      schedule.keyPeriod(
        schedule.timeAt(TestPeriod - 1, schedule.periodDuration - 1.nanoseconds)
      ) == TestPeriod - 1
      schedule.keyPeriod(
        schedule.timeAt(TestPeriod, schedule.periodDuration - 1.nanoseconds)
      ) == TestPeriod

  test "keyPeriod maps times before the Unix epoch to period 0":
    let schedule = KeySchedule.init().expect("default schedule")
    check schedule.keyPeriod(initTime(-1, 0)) == 0

suite "Mix Key Ring":
  var
    schedule: KeySchedule
    ring: MixKeyRing

  setup:
    schedule = KeySchedule.init().expect("default schedule")
    ring = MixKeyRing.new(
      schedule, rng(), replayTableCapacity = 16, publishedThrough = Opt.none(KeyPeriod)
    )

  template mid(period: KeyPeriod): Time =
    schedule.timeAt(period, schedule.periodDuration div 2)

  test "update generates the current and next keys":
    ring.update(mid(TestPeriod))

    let
      current = ring.publicKey(TestPeriod).expect("current key")
      next = ring.publicKey(TestPeriod + 1).expect("next key")
    check:
      ring.len == 2
      current != next
      ring.publicKey(TestPeriod - 1).isNone
      ring.publicKey(TestPeriod + 2).isNone

  test "update keeps the key of a key period":
    ring.update(schedule.timeAt(TestPeriod, chronos.seconds(1)))
    let current = ring.publicKey(TestPeriod).expect("current key")

    ring.update(mid(TestPeriod))
    check:
      ring.len == 2
      ring.publicKey(TestPeriod).get() == current

  test "keys follow the key period lifecycle":
    ring.update(mid(TestPeriod))

    # Next: published but not accepted
    check ring.candidates(mid(TestPeriod)).periods == @[TestPeriod]
    check ring.candidates(
      schedule.timeAt(
        TestPeriod, schedule.periodDuration - schedule.earlyWindow - 1.nanoseconds
      )
    ).periods == @[TestPeriod]

    # Next, early window: tried after the current key
    check ring.candidates(
      schedule.timeAt(TestPeriod, schedule.periodDuration - schedule.earlyWindow)
    ).periods == @[TestPeriod, TestPeriod + 1]

    # Current, with the previous key in its grace window
    ring.update(schedule.periodStart(TestPeriod + 1))
    check:
      ring.len == 3
      ring.candidates(schedule.periodStart(TestPeriod + 1)).periods ==
        @[TestPeriod + 1, TestPeriod]

      ring.candidates(
        schedule.timeAt(TestPeriod + 1, schedule.graceWindow - 1.nanoseconds)
      ).periods == @[TestPeriod + 1, TestPeriod]

    # Destroyed: not accepted once the grace window ends, even before update
    let
      graceEnd = schedule.timeAt(TestPeriod + 1, schedule.graceWindow)
      previous = ring.candidates(schedule.periodStart(TestPeriod + 1))[1]
    check ring.candidates(graceEnd).periods == @[TestPeriod + 1]

    ring.update(graceEnd)
    check:
      ring.len == 2
      ring.publicKey(TestPeriod).isNone
      previous.isDestroyed

  test "at most three keys are held and two accepted":
    ring.update(mid(TestPeriod))

    let step = chronos.seconds(30)
    var
      offset = ZeroDuration
      maxHeld, maxAccepted: int
    while offset < 3 * schedule.periodDuration:
      let now = schedule.timeAt(TestPeriod, offset)
      ring.update(now)
      let accepted = ring.candidates(now).len
      check accepted >= 1
      maxHeld = max(maxHeld, ring.len)
      maxAccepted = max(maxAccepted, accepted)
      offset += step

    check:
      maxHeld == 3
      maxAccepted == 2

  test "a restarted ring skips the periods it may have published":
    let restarted = MixKeyRing.new(
      schedule,
      rng(),
      replayTableCapacity = 16,
      publishedThrough = Opt.some(TestPeriod + 1),
    )
    restarted.update(mid(TestPeriod))
    check:
      restarted.len == 0
      restarted.candidates(mid(TestPeriod)).len == 0

    restarted.update(schedule.periodStart(TestPeriod + 1))
    check:
      restarted.len == 1
      restarted.publicKey(TestPeriod + 1).isNone
      restarted.publicKey(TestPeriod + 2).isSome
      restarted.candidates(mid(TestPeriod + 1)).len == 0
      restarted.candidates(mid(TestPeriod + 2)).periods == @[TestPeriod + 2]

  test "keys are generated independently":
    ring.update(mid(TestPeriod))
    let other = MixKeyRing.new(
      schedule, rng(), replayTableCapacity = 16, publishedThrough = Opt.none(KeyPeriod)
    )
    other.update(mid(TestPeriod))

    check:
      ring.publicKey(TestPeriod).get() != other.publicKey(TestPeriod).get()
      ring.publicKey(TestPeriod + 1).get() != other.publicKey(TestPeriod + 1).get()

  test "a clock stepping back into the early window keeps both keys":
    ring.update(mid(TestPeriod - 1))
    ring.update(schedule.timeAt(TestPeriod, chronos.seconds(10)))
    let
      current = ring.publicKey(TestPeriod).get()
      next = ring.publicKey(TestPeriod + 1).get()

    ring.update(
      schedule.timeAt(TestPeriod - 1, schedule.periodDuration - chronos.seconds(20))
    )
    check:
      ring.len == 3
      ring.publicKey(TestPeriod).get() == current
      ring.publicKey(TestPeriod + 1).get() == next

  test "a clock stepping back a key period keeps both keys":
    ring.update(mid(TestPeriod - 1))
    ring.update(mid(TestPeriod))
    let
      current = ring.publicKey(TestPeriod).get()
      next = ring.publicKey(TestPeriod + 1).get()

    ring.update(mid(TestPeriod - 1))
    check:
      ring.len == 2
      ring.publicKey(TestPeriod - 1).isNone
      ring.candidates(mid(TestPeriod - 1)).len == 0

    ring.update(mid(TestPeriod))
    check:
      ring.publicKey(TestPeriod).get() == current
      ring.publicKey(TestPeriod + 1).get() == next

  test "a clock jumping forward destroys every expired key":
    ring.update(mid(TestPeriod))
    let held = ring.candidates(
      schedule.timeAt(TestPeriod, schedule.periodDuration - schedule.earlyWindow)
    )
    check held.len == 2

    ring.update(mid(TestPeriod + 5))
    check:
      ring.len == 2
      ring.publicKey(TestPeriod + 5).isSome
      ring.publicKey(TestPeriod + 6).isSome
      held[0].isDestroyed
      held[1].isDestroyed

  test "a corrected clock serves again from the key period after next":
    ring.update(mid(TestPeriod))
    ring.update(mid(TestPeriod + 5))
    let ahead = ring.candidates(mid(TestPeriod + 5))[0]

    # Keys for TestPeriod and TestPeriod + 1 were published, so they are not
    # generated again.
    ring.update(mid(TestPeriod))
    check:
      not ahead.isDestroyed
      ring.len == 2
      ring.candidates(mid(TestPeriod)).len == 0

    ring.update(schedule.periodStart(TestPeriod + 1))
    check:
      ring.publicKey(TestPeriod + 1).isNone
      ring.publicKey(TestPeriod + 2).isSome

    ring.update(schedule.periodStart(TestPeriod + 2))
    check ring.candidates(mid(TestPeriod + 2)).periods == @[TestPeriod + 2]

    # The keys made while the clock ran ahead are used when their periods come.
    for period in TestPeriod + 3 .. TestPeriod + 5:
      ring.update(schedule.periodStart(period))
    check ring.candidates(mid(TestPeriod + 5)) == @[ahead]

  test "a key period never gets a second key":
    var times = @[
      mid(TestPeriod - 1),
      mid(TestPeriod),
      mid(TestPeriod + 5), # the clock jumps ahead
      mid(TestPeriod), # and is corrected
      mid(TestPeriod - 1), # then steps back
      mid(TestPeriod),
    ]
    for period in TestPeriod + 1 .. TestPeriod + 7:
      times.add(schedule.periodStart(period))
      times.add(mid(period))

    var keys: Table[KeyPeriod, FieldElement]
    for now in times:
      ring.update(now)
      for period in TestPeriod - 1 .. TestPeriod + 8:
        let key = ring.publicKey(period)
        if key.isSome:
          check keys.mgetOrPut(period, key.get()) == key.get()
    check keys.len == 10

  test "a ring started with its clock ahead serves at once after the correction":
    ring.update(mid(TestPeriod + 5))
    let ahead = ring.candidates(mid(TestPeriod + 5))[0]

    # No key was published for TestPeriod or TestPeriod + 1, so both are
    # generated as soon as the clock is corrected.
    ring.update(mid(TestPeriod))
    check:
      ring.len == 4
      ring.candidates(mid(TestPeriod)).periods == @[TestPeriod]
      ring.publicKey(TestPeriod + 1).isSome

    for period in TestPeriod + 1 .. TestPeriod + 5:
      ring.update(schedule.periodStart(period))
    check ring.candidates(mid(TestPeriod + 5)) == @[ahead]

  test "a destroyed key refuses to multiply and empties its replay table":
    ring.update(mid(TestPeriod))
    let
      key = ring.candidates(mid(TestPeriod))[0]
      (_, alpha) = generateKeyPair().expect("generate keypair error")
    check:
      key.multiply(alpha).isOk
      key.addTag(makeTag(1)) == TagAdded

    ring.update(schedule.timeAt(TestPeriod + 1, schedule.graceWindow))
    check:
      key.isDestroyed
      key.multiply(alpha).isErr
      key.tagCount == 0
      not key.isTagSeen(makeTag(1))
      key.addTag(makeTag(2)) == TagCacheFull

  asyncTest "start updates the ring at each key period change":
    let fast = KeySchedule
      .init(
        periodDuration = 1.seconds,
        earlyWindow = 50.milliseconds,
        graceWindow = 200.milliseconds,
        maxClockOffset = ZeroDuration,
        maxTransit = 10.milliseconds,
      )
      .expect("fast schedule")
    let fastRing = MixKeyRing.new(
      fast, rng(), replayTableCapacity = 16, publishedThrough = Opt.none(KeyPeriod)
    )
    fastRing.start()
    defer:
      await fastRing.stop()

    let
      first = fastRing.candidates()[0]
      period = first.period

    # The loop destroys the first key once the grace window after its period ends.
    checkUntilTimeout:
      first.isDestroyed
      fastRing.publicKey(period).isNone
      fastRing.publicKey(period + 1).isSome
      fastRing.publicKey(period + 2).isSome

suite "Replay Table":
  var key: MixKey

  setup:
    let
      schedule = KeySchedule.init().expect("default schedule")
      ring = MixKeyRing.new(
        schedule, rng(), replayTableCapacity = 2, publishedThrough = Opt.none(KeyPeriod)
      )
      now = schedule.periodStart(TestPeriod)
    ring.update(now)
    key = ring.candidates(now)[0]

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
