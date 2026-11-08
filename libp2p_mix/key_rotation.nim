# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Mix key ring, per-key replay tables, and their rotation config.
##
## Spec: https://lip.logos.co/anoncomms/raw/mix-key-rotation.html
## Section references of the form `Mix Key Rotation spec §N` point there.

{.push raises: [].}

import std/sets
import chronicles, chronos, results
import libp2p/crypto/[crypto, curve25519]
import nimcrypto/utils # burnMem
import ./[curve25519, tag_manager]

logScope:
  topics = "key_rotation"

export results

const
  DefaultRotationInterval* = chronos.hours(1) ## Rotation interval (spec: U).

  DefaultGraceWindow* = chronos.minutes(90) ## Grace window (spec: G).

  DefaultReplacedRecordLifetime* = chronos.minutes(15)
    ## Assumed bound on how long a replaced record can still be obtained (spec: D).

  DefaultMaxTransit* = chronos.minutes(1)
    ## Assumed bound on a packet's transit time (spec: max_transit).

type KeyRotationConfig* = object
  ## Key rotation timing, checked against the spec constraints by `init`.
  rotationInterval: Duration
  graceWindow: Duration

func validateKeyRotationConfig(
    rotationInterval, graceWindow, replacedRecordLifetime, maxTransit: Duration
): Result[void, string] =
  ## Reject timings under which an initiating node could still use a key the
  ## node no longer accepts (Mix Key Rotation spec §5, §8).
  if rotationInterval <= ZeroDuration:
    return err("rotationInterval (" & $rotationInterval & ") must be > 0")
  if replacedRecordLifetime < ZeroDuration:
    return err("replacedRecordLifetime (" & $replacedRecordLifetime & ") must be >= 0")
  if maxTransit < ZeroDuration:
    return err("maxTransit (" & $maxTransit & ") must be >= 0")
  let minGrace = rotationInterval + replacedRecordLifetime + 2 * maxTransit
  if graceWindow <= minGrace:
    return err(
      "graceWindow (" & $graceWindow &
        ") must be > rotationInterval + replacedRecordLifetime + 2 * maxTransit (" &
        $minGrace & ")"
    )
  ok()

static:
  let check = validateKeyRotationConfig(
    DefaultRotationInterval, DefaultGraceWindow, DefaultReplacedRecordLifetime,
    DefaultMaxTransit,
  )
  doAssert check.isOk, check.error

func init*(
    T: typedesc[KeyRotationConfig],
    rotationInterval: Duration = DefaultRotationInterval,
    graceWindow: Duration = DefaultGraceWindow,
    replacedRecordLifetime: Duration = DefaultReplacedRecordLifetime,
    maxTransit: Duration = DefaultMaxTransit,
): Result[T, string] =
  ## replacedRecordLifetime and maxTransit are the deployment's bounds; they
  ## constrain graceWindow and are not stored.
  ?validateKeyRotationConfig(
    rotationInterval, graceWindow, replacedRecordLifetime, maxTransit
  )
  ok(T(rotationInterval: rotationInterval, graceWindow: graceWindow))

func rotationInterval*(config: KeyRotationConfig): Duration =
  config.rotationInterval

func graceWindow*(config: KeyRotationConfig): Duration =
  config.graceWindow

func acceptanceWindow*(config: KeyRotationConfig): Duration =
  ## How long each key is accepted (Mix Key Rotation spec §3.4).
  config.rotationInterval + config.graceWindow

type MixKey* = ref object
  ## A mix key, and the replay table of the tags seen under it. Destroying it
  ## wipes both.
  privateKey: FieldElement
  publicKey: FieldElement
  tags: HashSet[Tag]
  capacity: int
  expiresAt: Opt[Moment] ## End of the grace window, once the key is replaced
  destroyed: bool

func publicKey*(key: MixKey): FieldElement =
  key.publicKey

func isDestroyed*(key: MixKey): bool =
  key.destroyed

func isAccepted*(key: MixKey, now: Moment): bool =
  ## False once the key is destroyed or its grace window has ended.
  not key.destroyed and (key.expiresAt.isNone or now < key.expiresAt.get())

func tagCount*(key: MixKey): int =
  key.tags.len

func isTagSeen*(key: MixKey, tag: Tag): bool =
  tag in key.tags

func isReplayTableFull*(key: MixKey): bool =
  key.tags.len >= key.capacity

proc multiply*(key: MixKey, point: FieldElement): Result[FieldElement, string] =
  ## point multiplied by this key's private scalar (X25519).
  if key.destroyed:
    return err("Destroyed mix key")
  var scalars = [key.privateKey]
  defer:
    burnMem(scalars)
  ok(multiplyPointWithScalars(point, scalars))

proc addTag*(key: MixKey, tag: Tag): TagInsertStatus =
  ## Tags are never evicted: a removed tag would let its packet be replayed
  ## while the key is still accepted (Mix Key Rotation spec §3.4). A destroyed
  ## key refuses every tag.
  if tag in key.tags:
    return TagAlreadyPresent
  if key.destroyed or key.isReplayTableFull:
    return TagCacheFull
  key.tags.incl(tag)
  if key.tags.len == key.capacity:
    warn "Replay table full, discarding further packets for this key",
      capacity = key.capacity
  TagAdded

proc destroy(key: MixKey) =
  burnMem(key.privateKey)
  key.tags = initHashSet[Tag]()
  key.destroyed = true

type KeyHandler* = proc(publicKey: FieldElement) {.gcsafe, raises: [].}
  ## Receives each new current public key, to publish in place of the previous
  ## one. A node that does not relay packets for others does not publish its key
  ## (Mix Key Rotation spec §4). It runs inside the ring's updates, so it should
  ## return without blocking.

type MixKeyRing* = ref object
  ## The mix keys a node holds: the current key, then the replaced keys from
  ## the most recently replaced (Mix Key Rotation spec §3.1). Keys are held in
  ## memory only.
  config: KeyRotationConfig
  rng: Rng
  replayTableCapacity: int
  keys: seq[MixKey]
  generatedAt: Moment ## When the current key was generated
  keyHandler: KeyHandler
  rotationLoop: Future[void].Raising([CancelledError])

proc initRing(
    config: KeyRotationConfig, rng: Rng, replayTableCapacity: int
): MixKeyRing =
  # Not generic, so its checks bind here rather than at each caller of `new`.
  doAssert config.rotationInterval > ZeroDuration,
    "config must come from KeyRotationConfig.init"
  doAssert not rng.isNil, "rng must not be nil"
  doAssert replayTableCapacity > 0,
    "replayTableCapacity (" & $replayTableCapacity & ") must be > 0"
  MixKeyRing(config: config, rng: rng, replayTableCapacity: replayTableCapacity)

proc new*(
    T: typedesc[MixKeyRing],
    config: KeyRotationConfig,
    rng: Rng,
    replayTableCapacity: int,
): T =
  ## replayTableCapacity is the number of tags each key's replay table holds;
  ## size it for the packets accepted over `config.acceptanceWindow`.
  initRing(config, rng, replayTableCapacity)

proc setKeyHandler*(ring: MixKeyRing, handler: KeyHandler) =
  ## The handler receives the current key at once, if there is one, then each
  ## new key.
  ring.keyHandler = handler
  if not handler.isNil and ring.keys.len > 0:
    handler(ring.keys[0].publicKey)

func len*(ring: MixKeyRing): int =
  ## Number of keys held.
  ring.keys.len

func currentPublicKey*(ring: MixKeyRing): Opt[FieldElement] =
  ## The key for this node's own hop (Mix Key Rotation spec §5), or none before
  ## the first update.
  if ring.keys.len == 0:
    return Opt.none(FieldElement)
  Opt.some(ring.keys[0].publicKey)

proc rotate(ring: MixKeyRing, now: Moment) =
  if ring.keys.len > 0:
    ring.keys[0].expiresAt = Opt.some(now + ring.config.graceWindow)
  var privateKey = Curve25519Key.random(ring.rng)
  let key = MixKey(
    privateKey: privateKey,
    publicKey: public(privateKey),
    capacity: ring.replayTableCapacity,
  )
  burnMem(privateKey)
  ring.keys.insert(key, 0)
  ring.generatedAt = now
  debug "Generated mix key", held = ring.keys.len
  if not ring.keyHandler.isNil:
    ring.keyHandler(key.publicKey)

proc update*(ring: MixKeyRing, now: Moment = Moment.now()) =
  ## Destroy each key whose grace window has ended, and generate a new current
  ## key if there is none or `rotationInterval` has passed since the current one
  ## was generated (Mix Key Rotation spec §3.2, §3.3).
  var kept: seq[MixKey]
  for key in ring.keys:
    if key.isAccepted(now):
      kept.add(key)
    else:
      key.destroy()
      debug "Destroyed mix key"
  ring.keys = kept

  if ring.keys.len == 0 or now - ring.generatedAt >= ring.config.rotationInterval:
    ring.rotate(now)

proc candidates*(ring: MixKeyRing, now: Moment = Moment.now()): seq[MixKey] =
  ## Keys to try on a received packet: the current key, then the replaced keys
  ## from the most recently replaced (Mix Key Rotation spec §6).
  var keys: seq[MixKey]
  for key in ring.keys:
    if key.isAccepted(now):
      keys.add(key)
  keys

func untilNextUpdate(ring: MixKeyRing, now: Moment): Duration =
  ## Time until the current key is due to be replaced or, if sooner, a replaced
  ## key's grace window ends.
  var next = ring.generatedAt + ring.config.rotationInterval
  for key in ring.keys:
    if key.expiresAt.isSome:
      next = min(next, key.expiresAt.get())
  next - now

proc rotationLoopProc(ring: MixKeyRing) {.async: (raises: [CancelledError]).} =
  while true:
    await sleepAsync(ring.untilNextUpdate(Moment.now()))
    ring.update()

proc start*(ring: MixKeyRing) =
  ## Generate the first key, then keep the ring updated in the background.
  ring.update()
  if ring.rotationLoop.isNil or ring.rotationLoop.finished:
    ring.rotationLoop = ring.rotationLoopProc()

proc stop*(ring: MixKeyRing) {.async: (raises: []).} =
  ## Stop the background updates and destroy every key, since nothing would
  ## destroy them once their grace windows end (Mix Key Rotation spec §3.3). A
  ## later start generates a new key.
  if not ring.rotationLoop.isNil:
    await ring.rotationLoop.cancelAndWait()
  for key in ring.keys:
    key.destroy()
  ring.keys = @[]
