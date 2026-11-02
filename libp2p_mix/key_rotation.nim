# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Mix key schedule, key ring, and per-key replay tables.
##
## Spec: https://lip.logos.co/anoncomms/raw/mix-key-rotation.html
## Section references of the form `Mix Key Rotation spec §N` point there.

{.push raises: [].}

import std/sets
from std/times import Time, getTime, toUnix, nanosecond, initTime
import chronicles, chronos, results
import libp2p/crypto/[crypto, curve25519]
import libp2p/utils/opt
import nimcrypto/utils # burnMem
import ./[curve25519, tag_manager]

logScope:
  topics = "key_rotation"

export results

const
  DefaultKeyPeriodDuration* = chronos.hours(3) ## Key period (spec: U).

  DefaultEarlyWindow* = chronos.minutes(1) ## Early window (spec: Q).

  DefaultGraceWindow* = chronos.minutes(15) ## Grace window (spec: V).

  DefaultMaxClockOffset* = chronos.seconds(15)
    ## Assumed bound on any node's clock offset (spec: max_clock_offset).

  DefaultMaxTransit* = chronos.minutes(1)
    ## Assumed bound on a packet's transit time (spec: max_transit).

type
  KeyPeriod* = uint64 ## Key period index, floor(t / periodDuration) for Unix time t.

  KeySchedule* = object
    ## Key rotation timing, checked against the spec constraints by `init`.
    periodDuration: Duration
    earlyWindow: Duration
    graceWindow: Duration

func validateKeySchedule(
    periodDuration, earlyWindow, graceWindow, maxClockOffset, maxTransit: Duration
): Result[void, string] =
  ## Reject timings that violate the early and grace window constraints
  ## (Mix Key Rotation spec §2, §10).
  if maxClockOffset < ZeroDuration:
    return err("maxClockOffset (" & $maxClockOffset & ") must be >= 0")
  if maxTransit < ZeroDuration:
    return err("maxTransit (" & $maxTransit & ") must be >= 0")
  if earlyWindow < 2 * maxClockOffset:
    return err(
      "earlyWindow (" & $earlyWindow & ") must be >= 2 * maxClockOffset (" &
        $(2 * maxClockOffset) & ")"
    )
  if graceWindow <= 2 * maxTransit + 2 * maxClockOffset:
    return err(
      "graceWindow (" & $graceWindow &
        ") must be > 2 * maxTransit + 2 * maxClockOffset (" &
        $(2 * maxTransit + 2 * maxClockOffset) & ")"
    )
  if periodDuration <= earlyWindow + graceWindow:
    return err(
      "periodDuration (" & $periodDuration & ") must be > earlyWindow + graceWindow (" &
        $(earlyWindow + graceWindow) & ")"
    )
  ok()

static:
  let check = validateKeySchedule(
    DefaultKeyPeriodDuration, DefaultEarlyWindow, DefaultGraceWindow,
    DefaultMaxClockOffset, DefaultMaxTransit,
  )
  doAssert check.isOk, check.error

func init*(
    T: typedesc[KeySchedule],
    periodDuration: Duration = DefaultKeyPeriodDuration,
    earlyWindow: Duration = DefaultEarlyWindow,
    graceWindow: Duration = DefaultGraceWindow,
    maxClockOffset: Duration = DefaultMaxClockOffset,
    maxTransit: Duration = DefaultMaxTransit,
): Result[T, string] =
  ## maxClockOffset and maxTransit are the deployment's bounds; they constrain
  ## the windows and are not stored.
  ?validateKeySchedule(
    periodDuration, earlyWindow, graceWindow, maxClockOffset, maxTransit
  )
  ok(
    T(
      periodDuration: periodDuration, earlyWindow: earlyWindow, graceWindow: graceWindow
    )
  )

func periodDuration*(schedule: KeySchedule): Duration {.inline.} =
  schedule.periodDuration

func earlyWindow*(schedule: KeySchedule): Duration {.inline.} =
  schedule.earlyWindow

func graceWindow*(schedule: KeySchedule): Duration {.inline.} =
  schedule.graceWindow

func acceptanceWindow*(schedule: KeySchedule): Duration =
  ## How long each key is accepted (Mix Key Rotation spec §4.4).
  schedule.earlyWindow + schedule.periodDuration + schedule.graceWindow

func sinceUnixEpoch(t: Time): Duration =
  chronos.seconds(t.toUnix()) + chronos.nanoseconds(t.nanosecond)

func startOffset(schedule: KeySchedule, period: KeyPeriod): Duration =
  ## start(period) as an offset from the Unix epoch.
  schedule.periodDuration * int64(period)

func keyPeriod*(schedule: KeySchedule, t: Time): KeyPeriod =
  ## key_period(t) (Mix Key Rotation spec §2). Times before the Unix epoch
  ## map to period 0.
  let elapsed = t.sinceUnixEpoch()
  if elapsed < ZeroDuration:
    return 0
  KeyPeriod(elapsed.nanoseconds div schedule.periodDuration.nanoseconds)

func periodStart*(schedule: KeySchedule, period: KeyPeriod): Time =
  ## start(period) (Mix Key Rotation spec §2). Overflows for periods past the
  ## year 2262, the range of a nanosecond int64.
  let ns = schedule.startOffset(period).nanoseconds
  initTime(ns div 1_000_000_000, ns mod 1_000_000_000)

type MixKey* = ref object
  ## The mix key for one key period, and the replay table of the tags seen
  ## under it.
  period: KeyPeriod
  privateKey: FieldElement
  publicKey: FieldElement
  tags: HashSet[Tag]
  capacity: int
  destroyed: bool

func period*(key: MixKey): KeyPeriod {.inline.} =
  key.period

func publicKey*(key: MixKey): FieldElement {.inline.} =
  key.publicKey

func privateKey*(key: MixKey): lent FieldElement {.inline.} =
  ## All zero once the key is destroyed.
  key.privateKey

func isDestroyed*(key: MixKey): bool {.inline.} =
  key.destroyed

func tagCount*(key: MixKey): int {.inline.} =
  key.tags.len

func isTagSeen*(key: MixKey, tag: Tag): bool {.inline.} =
  tag in key.tags

func isReplayTableFull*(key: MixKey): bool {.inline.} =
  key.tags.len >= key.capacity

proc addTag*(key: MixKey, tag: Tag): TagInsertStatus =
  ## Tags are never evicted: a removed tag would let its packet be replayed
  ## while the key is still accepted (Mix Key Rotation spec §4.4). A destroyed
  ## key refuses every tag.
  if tag in key.tags:
    return TagAlreadyPresent
  if key.destroyed or key.isReplayTableFull:
    return TagCacheFull
  key.tags.incl(tag)
  if key.tags.len == key.capacity:
    warn "Replay table full, discarding further packets for this key",
      period = key.period, capacity = key.capacity
  TagAdded

proc destroy(key: MixKey) =
  burnMem(key.privateKey)
  key.tags = initHashSet[Tag]()
  key.destroyed = true

type MixKeyRing* = ref object
  ## The mix keys a node holds: at most three, of which at most two are
  ## accepted at any time (Mix Key Rotation spec §4.1). A clock that runs ahead
  ## and is then corrected leaves more keys held until their grace windows end.
  ## Keys are held in memory only.
  schedule: KeySchedule
  rng: Rng
  replayTableCapacity: int
  keys: seq[MixKey]
  generatedRun: Opt[Slice[KeyPeriod]] ## Consecutive periods treated as generated
  generatedOutside: HashSet[KeyPeriod] ## Generated periods separated from the run
  rotationLoop: Future[void]

proc new*(
    T: typedesc[MixKeyRing],
    schedule: KeySchedule,
    rng: Rng,
    replayTableCapacity: int,
    publishedThrough: Opt[KeyPeriod],
): T =
  ## replayTableCapacity is the number of tags each key's replay table holds;
  ## size it for the packets accepted over `schedule.acceptanceWindow`.
  ##
  ## publishedThrough is the last key period this node may already have
  ## published a key for; the ring treats it and every earlier period as
  ## already generated (Mix Key Rotation spec §4.2). A node that has lost its
  ## keys passes the next key period of its clock, unless discovery shows it
  ## published none (Mix Key Rotation spec §4.5).
  doAssert schedule.periodDuration > ZeroDuration,
    "schedule must come from KeySchedule.init"
  doAssert not rng.isNil, "rng must not be nil"
  doAssert replayTableCapacity > 0,
    "replayTableCapacity (" & $replayTableCapacity & ") must be > 0"
  T(
    schedule: schedule,
    rng: rng,
    replayTableCapacity: replayTableCapacity,
    generatedRun: publishedThrough.map(
      proc(period: KeyPeriod): Slice[KeyPeriod] =
        0'u64 .. period
    ),
  )

func len*(ring: MixKeyRing): int {.inline.} =
  ## Number of keys held.
  ring.keys.len

func findKey(ring: MixKeyRing, period: KeyPeriod): Opt[MixKey] =
  for key in ring.keys:
    if key.period == period:
      return Opt.some(key)
  Opt.none(MixKey)

func publicKey*(ring: MixKeyRing, period: KeyPeriod): Opt[FieldElement] =
  ring.findKey(period).map(
    proc(key: MixKey): FieldElement =
      key.publicKey
  )

func isGenerated(ring: MixKeyRing, period: KeyPeriod): bool =
  (ring.generatedRun.isSome and period in ring.generatedRun.get()) or
    period in ring.generatedOutside

proc markGenerated(ring: MixKeyRing, period: KeyPeriod) =
  ## Merges the periods next to the run into it, so generatedOutside holds only
  ## the periods past a gap, such as those generated while the clock ran ahead.
  var run = ring.generatedRun.valueOr(period .. period)
  if period notin run:
    ring.generatedOutside.incl(period)
  while (run.b + 1) in ring.generatedOutside:
    run.b += 1
    ring.generatedOutside.excl(run.b)
  while run.a > 0 and (run.a - 1) in ring.generatedOutside:
    run.a -= 1
    ring.generatedOutside.excl(run.a)
  ring.generatedRun = Opt.some(run)

proc update*(ring: MixKeyRing, now: Time = getTime()) =
  ## Destroy each key whose grace window has ended, and generate the keys for
  ## the current and next key periods if missing (Mix Key Rotation spec §4.2,
  ## §4.3).
  let
    current = ring.schedule.keyPeriod(now)
    elapsed = now.sinceUnixEpoch()

  var kept: seq[MixKey]
  for key in ring.keys:
    if elapsed >= ring.schedule.startOffset(key.period + 1) + ring.schedule.graceWindow:
      key.destroy()
      debug "Destroyed mix key", period = key.period
    else:
      kept.add(key)
  ring.keys = kept

  for period in [current, current + 1]:
    # Never replace a key (Mix Key Rotation spec §4.2), including after the
    # clock steps back.
    if ring.isGenerated(period):
      continue
    var privateKey = Curve25519Key.random(ring.rng)
    ring.keys.add(
      MixKey(
        period: period,
        privateKey: privateKey,
        publicKey: public(privateKey),
        capacity: ring.replayTableCapacity,
      )
    )
    burnMem(privateKey)
    ring.markGenerated(period)
    debug "Generated mix key", period = period

proc candidates*(ring: MixKeyRing, now: Time = getTime()): seq[MixKey] =
  ## Keys to try on a received packet, current key first (Mix Key Rotation
  ## spec §7).
  let
    current = ring.schedule.keyPeriod(now)
    elapsed = now.sinceUnixEpoch()

  ring.findKey(current).withValue(key):
    result.add(key)
  if current > 0 and
      elapsed < ring.schedule.startOffset(current) + ring.schedule.graceWindow:
    ring.findKey(current - 1).withValue(key):
      result.add(key)
  if elapsed >= ring.schedule.startOffset(current + 1) - ring.schedule.earlyWindow:
    ring.findKey(current + 1).withValue(key):
      result.add(key)

func untilNextUpdate(ring: MixKeyRing, now: Time): Duration =
  ## Time until the next key period starts or, if sooner, the grace window of
  ## the previous key ends.
  let
    current = ring.schedule.keyPeriod(now)
    elapsed = now.sinceUnixEpoch()
    graceEnd = ring.schedule.startOffset(current) + ring.schedule.graceWindow

  var next = ring.schedule.startOffset(current + 1)
  if current > 0 and ring.findKey(current - 1).isSome and elapsed < graceEnd:
    next = graceEnd
  next - elapsed

func untilNextWake(ring: MixKeyRing, now: Time): Duration =
  ## Sleeps run on the monotonic clock, so a wall clock that jumps forward or a
  ## host that suspends would delay the next update. Waking at least once per
  ## early window bounds that delay.
  let wait = ring.untilNextUpdate(now)
  if ring.schedule.earlyWindow > ZeroDuration:
    min(wait, ring.schedule.earlyWindow)
  else:
    wait

proc rotationLoopProc(ring: MixKeyRing) {.async: (raises: [CancelledError]).} =
  while true:
    await sleepAsync(ring.untilNextWake(getTime()))
    ring.update()

proc start*(ring: MixKeyRing) =
  ## Generate the current and next keys, then keep the ring updated in the
  ## background.
  ring.update()
  if ring.rotationLoop.isNil or ring.rotationLoop.finished:
    ring.rotationLoop = ring.rotationLoopProc()

proc stop*(ring: MixKeyRing) {.async: (raises: []).} =
  ## Stop the background updates and wait for them to finish. Held keys are kept.
  if not ring.rotationLoop.isNil:
    await ring.rotationLoop.cancelAndWait()
