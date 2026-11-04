# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Mix key schedule, key ring, per-key replay tables, and published key entries.
##
## Spec: https://lip.logos.co/anoncomms/raw/mix-key-rotation.html
## Section references of the form `Mix Key Rotation spec §N` point there.

{.push raises: [].}

import std/sets
from std/times import Time, getTime, toUnix, nanosecond, initTime
import chronicles, chronos, results
import libp2p/crypto/[crypto, curve25519]
import libp2p/protobuf/minprotobuf
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
  ## Reject timings that violate the early and grace window constraints, or leave
  ## no time to change published entries (Mix Key Rotation spec §2, §5.1, §10).
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
  if periodDuration <= 2 * earlyWindow:
    return err(
      "periodDuration (" & $periodDuration & ") must be > 2 * earlyWindow (" &
        $(2 * earlyWindow) & ")"
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

func periodDuration*(schedule: KeySchedule): Duration =
  schedule.periodDuration

func earlyWindow*(schedule: KeySchedule): Duration =
  schedule.earlyWindow

func graceWindow*(schedule: KeySchedule): Duration =
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

type MixKeyEntries* = object
  ## The public keys a node publishes for keyPeriod and keyPeriod + 1 (Mix Key
  ## Rotation spec §5.2).
  keyPeriod*: KeyPeriod
  key*: FieldElement
  nextKey*: FieldElement

proc encode*(entries: MixKeyEntries): seq[byte] =
  var pb = initProtoBuffer()
  pb.write(1, entries.keyPeriod)
  pb.write(2, entries.key)
  pb.write(3, entries.nextKey)
  pb.finish()
  pb.buffer

proc decodeKey(
    pb: ProtoBuffer, field: int, name: string
): Result[FieldElement, string] =
  var key: seq[byte]
  discard pb.getField(field, key).valueOr:
    return err(name & ": " & $error)
  if key.len != FieldElementSize:
    return
      err(name & " (" & $key.len & " bytes) must be " & $FieldElementSize & " bytes")
  bytesToFieldElement(key)

proc decode*(T: typedesc[MixKeyEntries], data: openArray[byte]): Result[T, string] =
  ## Rejects data of exactly FieldElementSize bytes, which is a single unrotated
  ## key rather than entries.
  if data.len == FieldElementSize:
    return err("data (" & $data.len & " bytes) is a single unrotated key")

  let pb = initProtoBuffer(@data)
  var keyPeriod: uint64
  discard pb.getField(1, keyPeriod).valueOr:
    return err("key_period: " & $error)
  ok(
    T(
      keyPeriod: keyPeriod,
      key: ?pb.decodeKey(2, "key"),
      nextKey: ?pb.decodeKey(3, "next_key"),
    )
  )

type MixKey* = ref object
  ## The mix key for one key period, and the replay table of the tags seen
  ## under it.
  period: KeyPeriod
  privateKey: FieldElement
  publicKey: FieldElement
  tags: HashSet[Tag]
  capacity: int
  destroyed: bool

func period*(key: MixKey): KeyPeriod =
  key.period

func publicKey*(key: MixKey): FieldElement =
  key.publicKey

func isDestroyed*(key: MixKey): bool =
  key.destroyed

func tagCount*(key: MixKey): int =
  key.tags.len

func isTagSeen*(key: MixKey, tag: Tag): bool =
  tag in key.tags

func isReplayTableFull*(key: MixKey): bool =
  key.tags.len >= key.capacity

proc multiply*(key: MixKey, point: FieldElement): Result[FieldElement, string] =
  ## point multiplied by this key's private scalar (X25519).
  if key.destroyed:
    return err("Destroyed mix key: period " & $key.period)
  var scalars = [key.privateKey]
  defer:
    burnMem(scalars)
  ok(multiplyPointWithScalars(point, scalars))

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

type KeyEntriesHandler* = proc(entries: Opt[MixKeyEntries]) {.gcsafe, raises: [].}
  ## Receives each change of the entries to publish; none means publish nothing.
  ## It runs inside the ring's updates, so it should return without blocking.

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
  published: Opt[MixKeyEntries]
  entriesChange: Opt[tuple[period: KeyPeriod, at: Duration]]
    ## When the entries for period replace the published ones, as an offset from
    ## the Unix epoch
  entriesHandler: KeyEntriesHandler
  rotationLoop: Future[void]

proc initRing(
    schedule: KeySchedule,
    rng: Rng,
    replayTableCapacity: int,
    publishedThrough: Opt[KeyPeriod],
): MixKeyRing =
  # Not generic, so its checks bind here rather than at each caller of `new`.
  doAssert schedule.periodDuration > ZeroDuration,
    "schedule must come from KeySchedule.init"
  doAssert not rng.isNil, "rng must not be nil"
  doAssert replayTableCapacity > 0,
    "replayTableCapacity (" & $replayTableCapacity & ") must be > 0"
  MixKeyRing(
    schedule: schedule,
    rng: rng,
    replayTableCapacity: replayTableCapacity,
    generatedRun: publishedThrough.map(
      proc(period: KeyPeriod): Slice[KeyPeriod] =
        0'u64 .. period
    ),
  )

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
  initRing(schedule, rng, replayTableCapacity, publishedThrough)

proc setEntriesHandler*(ring: MixKeyRing, handler: KeyEntriesHandler) =
  ## Set before `start`, which publishes the first entries.
  ring.entriesHandler = handler

func publishedEntries*(ring: MixKeyRing): Opt[MixKeyEntries] =
  ## The entries to publish, or none while the node cannot process packets under
  ## both its current and next keys (Mix Key Rotation spec §4.5).
  ring.published

func len*(ring: MixKeyRing): int =
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

proc currentPublicKey*(ring: MixKeyRing, now: Time = getTime()): Opt[FieldElement] =
  ## The key for this node's own hop in a packet built at now (Mix Key Rotation
  ## spec §6.1).
  ring.publicKey(ring.schedule.keyPeriod(now))

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

proc updateEntries(ring: MixKeyRing, current: KeyPeriod, elapsed: Duration) =
  ## Publish the entries for current at its change time, or at once when no
  ## entries or older ones are published (Mix Key Rotation spec §4.5, §5.1).
  if ring.entriesChange.isNone or ring.entriesChange.get().period != current:
    let
      earliest = ring.schedule.earlyWindow
      span = ring.schedule.periodDuration div 2 - earliest
      offset = ring.rng.generate(uint64) mod uint64(span.nanoseconds)
    ring.entriesChange = Opt.some(
      (
        period: current,
        at:
          ring.schedule.startOffset(current) + earliest +
          chronos.nanoseconds(int64(offset)),
      )
    )

  var entries = Opt.none(MixKeyEntries)
  let key = ring.findKey(current)
  let nextKey = ring.findKey(current + 1)
  if key.isSome and nextKey.isSome:
    entries = Opt.some(
      MixKeyEntries(
        keyPeriod: current, key: key.get().publicKey, nextKey: nextKey.get().publicKey
      )
    )
    # The entries for current - 1 stay published until the change time, for
    # initiating nodes whose clocks lag (Mix Key Rotation spec §5.1).
    if ring.published.isSome and ring.published.get().keyPeriod + 1 == current and
        elapsed < ring.entriesChange.get().at:
      entries = ring.published

  if entries != ring.published:
    ring.published = entries
    debug "Changed published key entries", published = entries.isSome, period = current
    if not ring.entriesHandler.isNil:
      ring.entriesHandler(entries)

proc update*(ring: MixKeyRing, now: Time = getTime()) =
  ## Destroy each key whose grace window has ended, generate the keys for the
  ## current and next key periods if missing, and update the published entries
  ## (Mix Key Rotation spec §4.2, §4.3, §5.1).
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

  ring.updateEntries(current, elapsed)

proc candidates*(ring: MixKeyRing, now: Time = getTime()): seq[MixKey] =
  ## Keys to try on a received packet, current key first (Mix Key Rotation
  ## spec §7).
  let
    current = ring.schedule.keyPeriod(now)
    elapsed = now.sinceUnixEpoch()

  var keys: seq[MixKey]
  ring.findKey(current).withValue(key):
    keys.add(key)
  if current > 0 and
      elapsed < ring.schedule.startOffset(current) + ring.schedule.graceWindow:
    ring.findKey(current - 1).withValue(key):
      keys.add(key)
  if elapsed >= ring.schedule.startOffset(current + 1) - ring.schedule.earlyWindow:
    ring.findKey(current + 1).withValue(key):
      keys.add(key)
  keys

func untilNextUpdate(ring: MixKeyRing, now: Time): Duration =
  ## Time until the next key period starts or, if sooner, the grace window of
  ## the previous key ends or the published entries change.
  let
    current = ring.schedule.keyPeriod(now)
    elapsed = now.sinceUnixEpoch()
    graceEnd = ring.schedule.startOffset(current) + ring.schedule.graceWindow

  var next = ring.schedule.startOffset(current + 1)
  if current > 0 and ring.findKey(current - 1).isSome and elapsed < graceEnd:
    next = graceEnd
  if ring.entriesChange.isSome:
    let change = ring.entriesChange.get()
    if change.period == current and elapsed < change.at:
      next = min(next, change.at)
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
