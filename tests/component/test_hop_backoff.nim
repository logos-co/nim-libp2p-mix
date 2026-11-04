# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import std/strutils
import chronos, results
import libp2p/switch
import libp2p_mix
import libp2p_mix/mix_protocol
import ../tools/[lifecycle, unittest]
import ../utils

when defined(libp2p_mix_experimental_exit_is_dest):
  const TestCodec = "/mix/test/hop-backoff/1.0.0"

  proc firstHopFailed(sender: MixProtocol, exit: MixProtocol): Future[bool] {.async.} =
    let res = await sender.anonymizeLocalProtocolSend(
      newAsyncQueue[seq[byte]](),
      @[1.byte],
      TestCodec,
      MixDestination.exitNode(exit.switch.peerInfo.peerId),
      0,
    )
    if res.isErr and "Failed to dial to next hop" in res.error:
      return true
    if res.isErr:
      checkpoint res.error
    check res.isOk
    false

  proc firstHopFailures(
      sender: MixProtocol, exit: MixProtocol, sends: int
  ): Future[int] {.async.} =
    var failures = 0
    for _ in 0 ..< sends:
      if await sender.firstHopFailed(exit):
        inc failures
    failures

  proc sendUntilFirstHopFails(
      sender: MixProtocol, exit: MixProtocol, maxSends: int
  ): Future[bool] {.async.} =
    for _ in 0 ..< maxSends:
      if await sender.firstHopFailed(exit):
        return true
    false

  proc coverSelects(
      sender: MixProtocol, peerId: PeerId, builds: int
  ): Future[bool] {.async.} =
    for _ in 0 ..< builds:
      let cover = (await sender.buildCoverPacket(0)).expect("cover packet")
      if cover.firstHopPeerId == peerId:
        return true
    false

  suite "Hop backoff":
    asyncTeardown:
      checkTrackers()

    asyncTest "a hop that failed a dial is not selected again during the backoff":
      # nodes[0] sends to the exit nodes[5] through nodes[1 .. 4]. nodes[4] is
      # stopped, so without the backoff a quarter of the first hops are dead.
      let nodes = await setupMixNodes(6)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      await nodes[4].switch.stop()
      let first = await nodes[0].sendUntilFirstHopFails(nodes[5], 40)
      check first
      let later = await nodes[0].firstHopFailures(nodes[5], 30)
      check later == 0
      # The cover path draws its first node with the same filter.
      let coverSelected =
        await nodes[0].coverSelects(nodes[4].switch.peerInfo.peerId, 40)
      check not coverSelected

    asyncTest "a hop whose backoff ended is selected again":
      # A zero backoff ends at once, so the next send can select the hop again.
      let nodes = await setupMixNodes(6, hopBackoff = ZeroDuration)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      await nodes[4].switch.stop()
      let first = await nodes[0].sendUntilFirstHopFails(nodes[5], 40)
      check first
      let again = await nodes[0].sendUntilFirstHopFails(nodes[5], 40)
      check again

    asyncTest "a dial that succeeds clears the backoff":
      let nodes = await setupMixNodes(6)
      await startNodes(nodes)
      defer:
        await stopNodes(nodes)
      let hop = nodes[4].localMixPubInfo()
      await nodes[4].switch.stop()
      let first = await nodes[0].sendUntilFirstHopFails(nodes[5], 40)
      check first
      await nodes[4].switch.start()
      # A normal send never selects a backed off hop, so a direct cover send forces
      # the dial. The payload is not a valid packet, and the receiver drops it.
      let sent = await nodes[0].sendCoverPacket(hop.peerId, hop.multiAddr, @[1.byte])
      check sent.isOk
      let coverSelected = await nodes[0].coverSelects(hop.peerId, 100)
      check coverSelected
