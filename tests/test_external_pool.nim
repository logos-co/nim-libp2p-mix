# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/[sequtils, tables]
import chronos, results
import libp2p/[peerid, multiaddress, crypto/crypto, crypto/secp]
import libp2p_mix/[mix_node, mix_pool, external_pool]
import ./tools/[unittest, crypto]

type FakeHost = ref object
  ## A host with a table of peers and a fixed answer for the reply hop.
  peers: Table[PeerId, MixPubInfo]
  replyPeer: Opt[PeerId]
  selections: int

proc record(host: FakeHost, peerId: PeerId): MixPeerRecord =
  host.peers.withValue(peerId, info):
    return MixPeerRecord(
      mixPubKey: info.mixPubKey,
      publicKey: PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey),
      addresses: @[info.multiAddr],
    )
  MixPeerRecord()

proc answer(host: FakeHost, ctx: BrokerContext, withReplySelection = true) =
  ## Register the host's providers on `ctx`, as a host does at start.
  discard ReadMixPeer.reprovideIt(ctx):
    ok(host.record(peerId))
  discard ListMixPeerIds.reprovideIt(ctx):
    ok(host.peers.keys.toSeq())
  if withReplySelection:
    discard SelectMixReplyPeer.reprovideIt(ctx):
      host.selections.inc()
      return host.replyPeer
        .map(
          proc(p: PeerId): Result[PeerId, string] =
            ok(p)
        )
        .get(err("no reply peer"))

proc clear(ctx: BrokerContext) =
  ReadMixPeer.clearProvider(ctx)
  ListMixPeerIds.clearProvider(ctx)
  SelectMixReplyPeer.clearProvider(ctx)

suite "External pool":
  test "the pool reads, counts and selects through the host's providers":
    let ctx = NewBrokerContext()
    defer:
      clear(ctx)
    let infos = MixNodeInfo.generateRandomMany(3, rng()).mapIt(it.toMixPubInfo())
    let host = FakeHost()
    for info in infos:
      host.peers[info.peerId] = info
    host.answer(ctx, withReplySelection = false)
    let pool = ExternalMixPool.new(ctx, rng())
    check pool.countUsable([]).get() == 3
    check pool.usablePeer(infos[0].peerId).get() == Opt.some(infos[0])
    check pool.usablePeer(PeerId.random(rng()).get()).get().isNone
    let selected = pool.selectRandomNodes(2, [infos[0].peerId]).get()
    check selected.len == 2 and selected.allIt(it.peerId != infos[0].peerId)
    # Without a reply selection provider, the pool takes a random usable peer.
    let replyPeer = (waitFor pool.selectReplyPeer(@[infos[0].peerId])).get()
    check replyPeer in [infos[1].peerId, infos[2].peerId]
    check host.selections == 0

  test "the host's reply selection is used when it is provided":
    let ctx = NewBrokerContext()
    defer:
      clear(ctx)
    let infos = MixNodeInfo.generateRandomMany(2, rng()).mapIt(it.toMixPubInfo())
    let host = FakeHost(replyPeer: Opt.some(infos[1].peerId))
    for info in infos:
      host.peers[info.peerId] = info
    host.answer(ctx)
    let pool = ExternalMixPool.new(ctx, rng())
    check (waitFor pool.selectReplyPeer(@[infos[0].peerId])).get() == infos[1].peerId
    check host.selections == 1
    host.replyPeer = Opt.none(PeerId)
    check (waitFor pool.selectReplyPeer(@[])).isErr

  test "a cancelled reply selection cancels the host's pending answer":
    let ctx = NewBrokerContext()
    defer:
      clear(ctx)
    let answering = newAsyncEvent()
    var cancelled = false
    discard SelectMixReplyPeer.reprovideIt(ctx):
      answering.fire()
      try:
        await newAsyncEvent().wait()
      except CancelledError as exc:
        cancelled = true
        raise exc
      return err("the host never answers")
    let pool = ExternalMixPool.new(ctx, rng())
    let selecting = pool.selectReplyPeer(@[])
    waitFor answering.wait()
    waitFor selecting.cancelAndWait()
    check cancelled

  test "a missing or failing provider fails the read":
    let ctx = NewBrokerContext()
    defer:
      clear(ctx)
    let pool = ExternalMixPool.new(ctx, rng())
    let info = MixNodeInfo.generateRandom(0, rng()).toMixPubInfo()
    check pool.usablePeer(info.peerId).isErr
    check pool.countUsable([]).isErr
    check pool.selectRandomNodes(1, []).isErr
    discard ReadMixPeer.reprovideIt(ctx):
      err("host unavailable")
    discard ListMixPeerIds.reprovideIt(ctx):
      ok(@[info.peerId])
    check pool.countUsable([]).isErr
    clear(ctx)
    check pool.countUsable([]).isErr
