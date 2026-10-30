# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## A test host pool. Like a host such as Delivery, it keeps its own peer store
## and exclusions, and answers MixProtocol through MixPool.

{.push raises: [].}

import std/[sets, sequtils, tables]
import results
import libp2p/[peerstore, peerid, multiaddress, crypto/crypto]
import ./crypto
import libp2p_mix/[mix_pool, pool, mix_node, mix_protocol]

export mix_pool, pool

type HostPool* = ref object of MixPool
  store*: PeerStore
  excluded: HashSet[PeerId]

proc new*(T: typedesc[HostPool], store: PeerStore = nil): T =
  T(store: (if store.isNil: PeerStore.new() else: store), rng: rng())

method readPeer*(
    pool: HostPool, peerId: PeerId
): Result[MixPeerRecord, string] {.gcsafe, raises: [].} =
  if peerId in pool.excluded:
    return ok(MixPeerRecord())
  var addresses = pool.store[AddressBook][peerId]
  pool.store[LastSeenOutboundBook][peerId].withValue(address):
    addresses = @[address] & addresses.filterIt(it != address)
  ok(
    MixPeerRecord(
      mixPubKey: pool.store[MixPubKeyBook][peerId],
      publicKey: pool.store[KeyBook][peerId],
      addresses: addresses,
    )
  )

method listPeerIds*(
    pool: HostPool
): Result[seq[PeerId], string] {.gcsafe, raises: [].} =
  ok(pool.store[MixPubKeyBook].book.keys.toSeq().filterIt(it notin pool.excluded))

proc addPeer*(pool: HostPool, info: MixPubInfo) =
  ## Store a peer, replacing its keys and addresses.
  pool.store[MixPubKeyBook][info.peerId] = info.mixPubKey
  pool.store[KeyBook][info.peerId] =
    PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)
  pool.store[AddressBook].set(
    info.peerId, @[info.multiAddr], AddressConfidence.Infinite
  )

proc removePeer*(pool: HostPool, peerId: PeerId): bool =
  pool.store[MixPubKeyBook].del(peerId)

proc exclude*(pool: HostPool, peerId: PeerId) =
  pool.excluded.incl(peerId)

proc restore*(pool: HostPool, peerId: PeerId) =
  pool.excluded.excl(peerId)

proc nodePool*(mix: MixProtocol): MixNodePool =
  ## The stock pool of a MixProtocol made without a pool, as the old field.
  MixNodePool(mix.pool)
