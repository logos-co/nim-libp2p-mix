# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## The external pool. The peers live in the host, and this pool asks the host
## three questions through broker requests. The host answers them on the
## pool's broker context, from its own store, policy and connectivity. The
## library knows what it needs. It does not know who answers.

{.push raises: [].}

import chronos, results
import libp2p/[peerid, crypto/crypto]
import brokers/request_broker
import ./mix_pool

export request_broker, mix_pool

RequestBroker(sync):
  # The record of one peer after the host's policy. An empty record means the
  # peer is not a candidate.
  proc readMixPeer(peerId: PeerId): Result[MixPeerRecord, string]

RequestBroker(sync):
  # The IDs of the host's candidates. A repeated ID counts once.
  proc listMixPeerIds(): Result[seq[PeerId], string]

RequestBroker:
  # The final peer of a reply path, the hop that delivers the reply to this
  # node. A host that knows its connectivity prefers a connected peer. Without
  # this provider the pool takes a random usable peer.
  proc selectMixReplyPeer(
    excluded: seq[PeerId]
  ): Future[Result[PeerId, string]] {.async.}

type ExternalMixPool* = ref object of MixPool
  brokerCtx: BrokerContext

proc new*(T: typedesc[ExternalMixPool], brokerCtx: BrokerContext, rng: Rng): T =
  ## A pool that asks the providers registered on `brokerCtx`.
  T(brokerCtx: brokerCtx, rng: rng)

method readPeer*(
    pool: ExternalMixPool, peerId: PeerId
): Result[MixPeerRecord, string] {.gcsafe, raises: [].} =
  ReadMixPeer.request(pool.brokerCtx, peerId)

method listPeerIds*(
    pool: ExternalMixPool
): Result[seq[PeerId], string] {.gcsafe, raises: [].} =
  ListMixPeerIds.request(pool.brokerCtx)

method selectReplyPeer*(
    pool: ExternalMixPool, excluded: seq[PeerId]
): Future[Result[PeerId, string]] {.async: (raises: [CancelledError]).} =
  ## Ask the host. A cancelled caller also cancels the host's pending work.
  if not SelectMixReplyPeer.isProvided(pool.brokerCtx):
    return await procCall selectReplyPeer(MixPool(pool), excluded)
  let pending = SelectMixReplyPeer.request(pool.brokerCtx, excluded)
  try:
    # join keeps the caller's cancellation across the broker's exception handling.
    await pending.join()
    return await pending
  finally:
    await noCancel pending.cancelAndWait()
