# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, results
import libp2p/[switch, stream/lpstream, peerstore, peerid]
import libp2p_mix
import libp2p_mix/[mix_protocol, delay_strategy, mix_pool]
import ../tools/[lifecycle, unittest, crypto, host_pool]
import ../utils

type SelectingPool = ref object of HostPool
  ## Answers the reply selection for the test. `mode` makes it return an
  ## excluded peer, withdraw its choice, refuse the second selection, or fail
  ## one primitive ("read", "list" or "reply").
  mix: MixProtocol
  mode: string
  calls, credentialsAtSecond: int

method readPeer(
    pool: SelectingPool, peerId: PeerId
): Result[MixPeerRecord, string] {.gcsafe, raises: [].} =
  if pool.mode == "read":
    return err("read failed")
  procCall readPeer(HostPool(pool), peerId)

method listPeerIds(
    pool: SelectingPool
): Result[seq[PeerId], string] {.gcsafe, raises: [].} =
  if pool.mode == "list":
    return err("list failed")
  procCall listPeerIds(HostPool(pool))

method selectReplyPeer(
    pool: SelectingPool, excluded: seq[PeerId]
): Future[Result[PeerId, string]] {.async: (raises: [CancelledError]).} =
  if pool.mode == "reply":
    return err("reply selection failed")
  pool.calls.inc()
  if pool.mode == "excluded":
    return ok(excluded[^1])
  if pool.calls == 2:
    pool.credentialsAtSecond = pool.mix.surbCredsLen
    if pool.mode == "error":
      return err("host refused the second reply peer")
  let peer = (?pool.selectRandomNodes(1, excluded))[0].peerId
  if pool.mode == "withdrawn":
    discard pool.removePeer(peer)
  return ok(peer)

proc sendWithReplies(mode: string): Future[SelectingPool] {.async.} =
  ## Send one request with two SURBs through a fresh sender, expect it to
  ## fail, and return the sender's pool for the checks.
  let info = MixNodeInfo.generateRandom(0, rng())
  let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
  let pool = SelectingPool(mode: mode, store: PeerStore.new(), rng: rng())
  let mix = MixProtocol.new(
    info,
    sw,
    pool = pool,
    delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
  )
  pool.mix = mix
  let peers = MixNodeInfo.generateRandomMany(4, rng())
  for peer in peers:
    pool.addPeer(peer.toMixPubInfo())
  mix.registerDestReadBehavior("/test/reply-selection/1", readLp(1024))
  sw.mount(mix)
  await sw.start()
  defer:
    await stopNodes(@[mix])
  mix.setLocalMultiAddr(sw.peerInfo.addrs[0]).expect("bound sender address")
  let conn = mix
    .toConnection(
      MixDestination.exitNode(peers[^1].peerId),
      "/test/reply-selection/1",
      MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(2'u8)),
    )
    .get()
  defer:
    await conn.close()
  expect LPStreamError:
    await conn.writeLp(@[1'u8]).wait(2.seconds)
  check:
    mix.surbCredsLen == 0
    mix.switch.connectedPeers().len == 0
  return pool

suite "Pool selection of the final reply peer":
  asyncTeardown:
    checkTrackers()

  asyncTest "mix rejects an excluded or withdrawn selection":
    for mode in ["excluded", "withdrawn"]:
      let pool = await sendWithReplies(mode)
      check pool.calls == 1

  asyncTest "a later selection error releases credentials already registered":
    let pool = await sendWithReplies("error")
    check:
      pool.calls == 2
      pool.credentialsAtSecond == 1

  asyncTest "a pool error fails a send without a defect or retained credentials":
    for mode in ["list", "read", "reply"]:
      let pool = await sendWithReplies(mode)
      check pool.calls == 0
