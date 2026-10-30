# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Events that the Mix library emits for its host.

{.push raises: [].}

import std/tables
import chronos
import libp2p/peerid
import brokers/[event_broker, broker_context]

export event_broker, broker_context

EventBroker:
  ## Mix could not dial `peerId`, the next hop of a packet that this node sends
  ## or forwards. The packet is lost. A host can back the peer off.
  type MixHopDialFailed* = object
    peerId*: PeerId

proc cleanupDetachedMixHopDialFailedBucket(brokerCtx: BrokerContext) {.gcsafe.}

proc scheduleMixHopDialFailedCleanup(brokerCtx: BrokerContext) {.gcsafe.} =
  # The broker's emit loop can still hold a bucket index until it returns.
  callSoon(
    proc(_: pointer) {.gcsafe, raises: [].} =
      cleanupDetachedMixHopDialFailedBucket(brokerCtx)
  )

proc cleanupDetachedMixHopDialFailedBucket(brokerCtx: BrokerContext) {.gcsafe.} =
  let broker = accessMixHopDialFailedBroker()
  for i in 0 ..< broker.buckets.len:
    if broker.buckets[i].brokerCtx != brokerCtx:
      continue
    pruneInFlightMixHopDialFailed(broker, i)
    if broker.buckets[i].inFlight.len != 0:
      broker.buckets[i].inFlight[0].addCallback(
        proc(_: pointer) {.gcsafe, raises: [].} =
          scheduleMixHopDialFailedCleanup(brokerCtx)
      )
    # Keep the empty bucket. EventBroker.dropListener can also hold this index
    # across an await. Pruning releases callback references; a later listener
    # on this numeric context reuses the bucket.
    return

proc detachMixHopDialFailedListener*(
    brokerCtx: BrokerContext, handle: MixHopDialFailedListener
) =
  ## Remove a listener whose callback never suspends, without cancelling other
  ## listeners' active callbacks. EventBroker.dropListener cancels every
  ## in-flight callback in the context, regardless of its owner.
  if handle.id == 0'u64:
    return
  let broker = accessMixHopDialFailedBroker()
  for i in 0 ..< broker.buckets.len:
    if broker.buckets[i].brokerCtx != brokerCtx:
      continue
    broker.buckets[i].listeners.del(handle.id)
    pruneInFlightMixHopDialFailed(broker, i)
    scheduleMixHopDialFailedCleanup(brokerCtx)
    return
