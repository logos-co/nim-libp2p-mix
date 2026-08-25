# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## SURB reply credential store for the Mix Protocol.
##
## When a node attaches SURBs to an outgoing message it must retain the reply
## decryption keys until the reply arrives (spec Section 8.7.2 Step 4). If a
## reply never arrives the credentials would otherwise be held forever, so this
## store expires them after a configurable TTL:
##
##   Note: A SURB becomes unusable once any return-path mix node rotates its
##   X25519 key. Implementations SHOULD discard these tuples after a
##   configurable timeout, or at most by the key rotation interval.
##
## Cleanup is driven by the write path rather than by a timer. Unlike the replay
## tag cache -- which is fed by traffic forwarded on behalf of other peers at an
## uncontrolled rate -- this store is only ever written by locally originated
## sends, so tying the sweep to inserts covers all growth by construction. The
## background loop exists purely to reclaim memory on a node that has gone quiet
## after a burst.

{.push raises: [].}

import std/[sets, tables]
import chronicles, chronos, metrics
import libp2p/utils/[heartbeat, opt]
import results
import ./[mix_metrics, serialization, sphinx]

export results

const
  DefaultSurbCredsTTL* = chronos.minutes(30)
  DefaultSurbCredsPurgeInterval* = chronos.minutes(5)
  DefaultMaxSurbCreds* = 100_000
  MinSweepThreshold* = 1024

type
  SURBIdentifierGroup* = ref object
    ## All SURBs minted for a single send.
    ##
    ## `expiresAt` is stamped here rather than per credential, so a partially
    ## expired group is unrepresentable. The exit replies via *every* SURB in
    ## the group, so N replies race and the first must invalidate the rest.
    members: HashSet[SURBIdentifier]
    expiresAt: Moment

  ConnCreds* = object
    igroup*: SURBIdentifierGroup
    incoming*: AsyncQueue[seq[byte]]
    credential*: ReplyCredential

  SurbStore* = ref object
    creds: Table[SURBIdentifier, ConnCreds]
    sweepThreshold: int
    peakLen: int
    sweeps: int
    ttl: Duration
    maxCreds: int
    purgeInterval: Duration
    purgeLoop: Future[void]

  SurbSession* = ref object
    ## Handle to the credentials registered for one send. Carries just enough
    ## to release them, so a holder needs no reference to the MixProtocol.
    ## Nothing in the store points back here, so this introduces no cycle.
    store: SurbStore
    igroup: SURBIdentifierGroup

func len*(s: SurbStore): int {.inline.} =
  ## Credentials currently stored, including any expired but not yet swept.
  s.creds.len

func ttl*(s: SurbStore): Duration {.inline.} =
  s.ttl

func sweepCount*(s: SurbStore): int {.inline.} =
  ## Exposed so tests can assert the amortised policy does not degrade into
  ## sweeping on every insert.
  s.sweeps

func expiresAt*(g: SURBIdentifierGroup): Moment {.inline.} =
  g.expiresAt

proc rebuildIfSparse(s: SurbStore) =
  ## Nim's Table does not shrink its slot array on `del`, so a store that once
  ## peaked high keeps that allocation for the process lifetime.
  if s.peakLen <= MinSweepThreshold or s.creds.len * 4 >= s.peakLen:
    return

  var fresh = initTable[SURBIdentifier, ConnCreds](s.creds.len)
  for id, c in s.creds:
    fresh[id] = c
  s.creds = move(fresh)
  s.peakLen = s.creds.len

proc purgeExpired*(s: SurbStore, now: Moment = Moment.now()): int =
  ## Returns the number of credentials removed.
  ##
  ## Two passes because Nim does not permit deleting from a Table while
  ## iterating it; the intermediate seq is sized by the expired count.
  var expired: seq[SURBIdentifier]
  for id, c in s.creds:
    if c.igroup.expiresAt <= now:
      expired.add(id)

  for id in expired:
    s.creds.del(id)

  s.sweeps += 1
  s.sweepThreshold = max(MinSweepThreshold, s.creds.len * 2)
  s.rebuildIfSparse()

  if expired.len > 0:
    mix_surb_creds_expired.inc(expired.len.int64)
    mix_surb_creds_active.set(s.creds.len.int64)
    trace "Purged expired SURB credentials",
      count = expired.len, remaining = s.creds.len

  expired.len

proc newGroup*(s: SurbStore, now: Moment = Moment.now()): SURBIdentifierGroup =
  SURBIdentifierGroup(members: initHashSet[SURBIdentifier](), expiresAt: now + s.ttl)

proc add*(
    s: SurbStore, id: SURBIdentifier, creds: ConnCreds, now: Moment = Moment.now()
): Result[void, string] =
  ## Sweeps first if occupancy has crossed the threshold, which is then reset
  ## to twice the post-sweep size -- so each sweep requires at least that many
  ## further inserts, giving amortised O(1) per add.
  ##
  ## Also sweeps when at capacity regardless of the threshold, so a store whose
  ## cap sits below MinSweepThreshold still reclaims before refusing. That costs
  ## O(n) per add while full, which is acceptable: the send is being rejected
  ## anyway, so the caller is already in a back-off path.
  if s.creds.len >= min(s.sweepThreshold, s.maxCreds):
    discard s.purgeExpired(now)

  if s.creds.len >= s.maxCreds:
    # Reject rather than evict: evicting would destroy credentials belonging
    # to an unrelated in-flight request, turning memory pressure into a
    # correctness failure for a peer that did nothing wrong.
    mix_surb_creds_rejected.inc()
    return err(
      "SURB credential store at capacity (" & $s.maxCreds &
        "); too many replies outstanding"
    )

  creds.igroup.members.incl(id)
  s.creds[id] = creds
  s.peakLen = max(s.peakLen, s.creds.len)
  mix_surb_creds_active.set(s.creds.len.int64)
  ok()

proc get*(
    s: SurbStore, id: SURBIdentifier, now: Moment = Moment.now()
): Opt[ConnCreds] =
  ## Expired entries are invisible here whether or not a sweep has run yet.
  s.creds.withValue(id, c):
    if c.igroup.expiresAt <= now:
      return Opt.none(ConnCreds)
    return Opt.some(c[])
  Opt.none(ConnCreds)

proc release*(s: SurbStore, igroup: SURBIdentifierGroup) =
  ## Idempotent, so releasing twice or after expiry is safe.
  if igroup.isNil:
    return
  for id in igroup.members:
    s.creds.del(id)
  igroup.members.clear()
  mix_surb_creds_active.set(s.creds.len.int64)

func igroup*(s: SurbSession): SURBIdentifierGroup {.inline.} =
  s.igroup

proc newSession*(s: SurbStore, now: Moment = Moment.now()): SurbSession =
  SurbSession(store: s, igroup: s.newGroup(now))

proc release*(s: SurbSession) =
  ## Idempotent, like the underlying store release.
  if not s.isNil:
    s.store.release(s.igroup)

proc clear*(s: SurbStore) =
  s.creds.clear()
  s.peakLen = 0
  s.sweepThreshold = MinSweepThreshold
  mix_surb_creds_active.set(0)

proc purgeLoopProc(s: SurbStore) {.async: (raises: [CancelledError]).} =
  heartbeat "SURB creds purge", s.purgeInterval, sleepFirst = true:
    let purged = s.purgeExpired()
    if purged > 0:
      trace "Purged expired SURB credentials (idle backstop)",
        count = purged, remaining = s.creds.len

proc start*(s: SurbStore) =
  if s.purgeLoop.isNil or s.purgeLoop.finished:
    s.purgeLoop = s.purgeLoopProc()

proc stop*(s: SurbStore) {.async: (raises: []).} =
  if not s.purgeLoop.isNil:
    await s.purgeLoop.cancelAndWait()

proc stopSoon*(s: SurbStore) =
  if not s.purgeLoop.isNil:
    s.purgeLoop.cancelSoon()

proc new*(
    T: typedesc[SurbStore],
    ttl: Duration = DefaultSurbCredsTTL,
    purgeInterval: Duration = DefaultSurbCredsPurgeInterval,
    maxCreds: int = DefaultMaxSurbCreds,
    autoStart: bool = true,
): T =
  doAssert ttl > ZeroDuration, "SurbStore ttl must be positive"
  doAssert maxCreds > 0, "SurbStore maxCreds must be greater than zero"

  let s = T(
    creds: initTable[SURBIdentifier, ConnCreds](),
    sweepThreshold: MinSweepThreshold,
    ttl: ttl,
    maxCreds: maxCreds,
    purgeInterval: purgeInterval,
  )
  if autoStart:
    s.start()
  s
