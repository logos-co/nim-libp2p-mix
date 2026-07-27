# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos
import libp2p_mix/[serialization, surb_store]
import ./tools/unittest

proc makeId(seed: int): SURBIdentifier =
  for i in 0 ..< result.len:
    result[i] = byte((seed * 7 + i) mod 256)

proc makeCreds(igroup: SURBIdentifierGroup): ConnCreds =
  ConnCreds(
    igroup: igroup,
    incoming: newAsyncQueue[seq[byte]](),
    surbSecret: @[@[byte 1, 2, 3]],
    surbKey: @[byte 4, 5, 6],
  )

suite "SURB Store":
  var store: SurbStore
  let base = Moment.init(0, Millisecond)

  setup:
    # autoStart=false keeps the purge loop out of these synchronous tests
    store = SurbStore.new(ttl = chronos.minutes(30), autoStart = false)

  teardown:
    store.clear()

  test "add, get and release":
    let igroup = store.newGroup(base)
    let id = makeId(1)

    check store.len == 0
    check store.get(id, base).isNone()

    check store.add(id, makeCreds(igroup), base).isOk()
    check store.len == 1
    check store.get(id, base).isSome()

    store.release(igroup)
    check store.len == 0
    check store.get(id, base).isNone()

  test "release evicts every member of the group":
    let igroup = store.newGroup(base)
    for i in 0 .. 3:
      check store.add(makeId(i), makeCreds(igroup), base).isOk()
    check store.len == 4

    # Releasing via one member's group drops all siblings: the exit replies
    # through every SURB, so the first reply must invalidate the rest.
    let creds = store.get(makeId(0), base).valueOr:
      raiseAssert "just added"
    store.release(creds.igroup)

    check store.len == 0
    for i in 0 .. 3:
      check store.get(makeId(i), base).isNone()

  test "release is idempotent":
    let igroup = store.newGroup(base)
    check store.add(makeId(1), makeCreds(igroup), base).isOk()

    store.release(igroup)
    store.release(igroup)
    check store.len == 0

    # And after expiry has already removed the entries
    let expired = store.newGroup(base)
    check store.add(makeId(2), makeCreds(expired), base).isOk()
    discard store.purgeExpired(base + chronos.minutes(31))
    store.release(expired)
    check store.len == 0

  test "get hides expired entries before any sweep runs":
    let igroup = store.newGroup(base)
    let id = makeId(1)
    check store.add(id, makeCreds(igroup), base).isOk()

    let justBefore = base + chronos.minutes(30) - chronos.milliseconds(1)
    check store.get(id, justBefore).isSome()

    # Expired but not yet swept: still resident, but invisible to lookups.
    let after = base + chronos.minutes(30)
    check store.get(id, after).isNone()
    check store.len == 1

  test "all members of a group expire together":
    let igroup = store.newGroup(base)
    for i in 0 .. 4:
      check store.add(makeId(i), makeCreds(igroup), base).isOk()

    check store.purgeExpired(base + chronos.minutes(29)) == 0
    check store.len == 5

    check store.purgeExpired(base + chronos.minutes(30)) == 5
    check store.len == 0

  test "purge only removes groups past their own deadline":
    let old = store.newGroup(base)
    check store.add(makeId(1), makeCreds(old), base).isOk()

    let fresh = store.newGroup(base + chronos.minutes(20))
    check store.add(makeId(2), makeCreds(fresh), base).isOk()

    check store.purgeExpired(base + chronos.minutes(31)) == 1
    check store.len == 1
    check store.get(makeId(2), base + chronos.minutes(31)).isSome()

  test "at capacity, add is rejected rather than evicting a live group":
    let small = SurbStore.new(maxCreds = 4, autoStart = false)
    defer:
      small.clear()

    let igroup = small.newGroup(base)
    for i in 0 .. 3:
      check small.add(makeId(i), makeCreds(igroup), base).isOk()
    check small.len == 4

    let rejected = small.add(makeId(99), makeCreds(small.newGroup(base)), base)
    check rejected.isErr()

    # The existing group is untouched: rejecting the new send is preferable to
    # destroying credentials for a request already in flight.
    check small.len == 4
    for i in 0 .. 3:
      check small.get(makeId(i), base).isSome()

  test "capacity is reclaimed once the resident group expires":
    let small = SurbStore.new(maxCreds = 2, autoStart = false)
    defer:
      small.clear()

    let igroup = small.newGroup(base)
    check small.add(makeId(1), makeCreds(igroup), base).isOk()
    check small.add(makeId(2), makeCreds(igroup), base).isOk()
    check small.add(makeId(3), makeCreds(small.newGroup(base)), base).isErr()

    # add() sweeps before rejecting, so a later attempt succeeds on its own.
    let later = base + chronos.minutes(31)
    check small.add(makeId(3), makeCreds(small.newGroup(later)), later).isOk()
    check small.len == 1

  test "sweeps stay amortised across many inserts":
    let igroup = store.newGroup(base)
    for i in 0 ..< 20_000:
      check store.add(makeId(i), makeCreds(igroup), base).isOk()

    # Doubling the threshold after each sweep keeps this logarithmic; a
    # per-insert sweep would be ~20_000.
    check store.sweepCount < 32

  test "clear drops everything":
    let igroup = store.newGroup(base)
    for i in 0 .. 2:
      check store.add(makeId(i), makeCreds(igroup), base).isOk()

    store.clear()
    check store.len == 0
    check store.get(makeId(0), base).isNone()

  test "ttl is rejected when not positive":
    expect Defect:
      discard SurbStore.new(ttl = ZeroDuration, autoStart = false)

  test "maxCreds is rejected when not positive":
    expect Defect:
      discard SurbStore.new(maxCreds = 0, autoStart = false)
