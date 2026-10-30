# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import chronos, metrics, results
import libp2p/[switch, stream/lpstream, peerstore, peerid, multiaddress]
import libp2p_mix
import libp2p_mix/[mix_protocol, delay_strategy, mix_pool, mix_metrics]
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

type PinnedPool = ref object of HostPool
  ## Answers the reply selection with one fixed peer, as a host that knows its
  ## connections does.
  replyPeer: PeerId

method selectReplyPeer(
    pool: PinnedPool, excluded: seq[PeerId]
): Future[Result[PeerId, string]] {.async: (raises: [CancelledError]).} =
  ok(pool.replyPeer)

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

  asyncTest "a failed reply selection counts POOL_UNAVAILABLE for the reply path":
    let before = mix_messages_error.value(["Entry/SURB", "POOL_UNAVAILABLE"])
    discard await sendWithReplies("reply")
    check mix_messages_error.value(["Entry/SURB", "POOL_UNAVAILABLE"]) == before + 1

  asyncTest "a host-chosen connected peer delivers the reply to a sender that no one can dial":
    let nodes = await startTestMixNodes(4)
    defer:
      await stopNodes(nodes)
    let echo = EchoProtocol.new()
    await echo.start()
    nodes[^1].switch.mount(echo)
    for node in nodes:
      node.registerDestReadBehavior(echo.codec, readLp(1024))
    # The sender advertises a port where nothing listens. The reply reaches it
    # only over the connection that the sender opened to the chosen peer.
    let info = MixNodeInfo.generateRandom(0, rng())
    let sw = createSwitch(info.multiAddr, Opt.some(info.libp2pPrivKey))
    let pool = PinnedPool(store: PeerStore.new(), rng: rng())
    let sender = MixProtocol.new(
      info,
      sw,
      pool = pool,
      delayStrategy = Opt.some(DelayStrategy(NoSamplingDelayStrategy.new(rng()))),
    )
    sender.registerDestReadBehavior(echo.codec, readLp(1024))
    sw.mount(sender)
    await sw.start()
    defer:
      await stopNodes(@[sender])
    sender.setLocalMultiAddr(MultiAddress.init("/ip4/127.0.0.1/tcp/1").get()).expect(
      "undialable sender address"
    )
    for node in nodes:
      pool.addPeer(node.localMixPubInfo())
    let replyPeer = nodes[0]
    pool.replyPeer = replyPeer.switch.peerInfo.peerId
    await sw.connect(replyPeer.switch.peerInfo.peerId, replyPeer.switch.peerInfo.addrs)
    let conn = sender
      .toConnection(
        MixDestination.exitNode(nodes[^1].localMixPubInfo().peerId),
        echo.codec,
        MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(1'u8)),
      )
      .get()
    defer:
      await conn.close()
    await conn.writeLp(@[9'u8]).wait(5.seconds)
    check:
      (await conn.readLp(1024).wait(5.seconds)) == @[9'u8]
      sw.connectedPeers(Direction.In).len == 0
      sender.surbCredsLen == 0
