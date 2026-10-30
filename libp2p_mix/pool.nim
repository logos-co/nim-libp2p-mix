# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Mix Node Pool
##
## `MixNodePool` is the stock `MixPool`. It stores mix nodes in the peer store
## of a libp2p switch, in the MixPubKeyBook, AddressBook and KeyBook, and reads
## them back for the mix protocol.

{.push raises: [].}

import std/[sequtils, tables]
import results
import libp2p/peerstore
import libp2p/peerid
import libp2p/multiaddress
import libp2p/crypto/crypto
import libp2p/crypto/curve25519
import ./mix_node
import ./mix_pool

export mix_pool

type MixPubKeyBook* = ref object of PeerBook[Curve25519Key]
  ## Tracks Curve25519 mix public keys per peer. Defined here so the mix
  ## package owns its peer-store extension and libp2p core stays free of
  ## mix-specific types.

type MixNodePool* = ref object of MixPool
  ## The stock pool. Keeps mix node information in a peer store, so other
  ## protocols on the same switch see the same addresses and keys.
  peerStore: PeerStore

proc new*(T: typedesc[MixNodePool], peerStore: PeerStore, rng: Rng): T =
  ## Create a pool on `peerStore`. `rng` drives its random selections.
  T(peerStore: peerStore, rng: rng)

method readPeer*(
    pool: MixNodePool, peerId: PeerId
): Result[MixPeerRecord, string] {.gcsafe, raises: [].} =
  ## Keys from the books, and the addresses with the last outbound one first.
  var addresses = pool.peerStore[AddressBook][peerId]
  pool.peerStore[LastSeenOutboundBook][peerId].withValue(address):
    addresses = @[address] & addresses.filterIt(it != address)
  ok(
    MixPeerRecord(
      mixPubKey: pool.peerStore[MixPubKeyBook][peerId],
      publicKey: pool.peerStore[KeyBook][peerId],
      addresses: addresses,
    )
  )

proc add*(pool: MixNodePool, info: MixPubInfo) =
  ## Add a mix node to the pool.
  ## MixPubKeyBook entry is always updated.
  ## Address is added to AddressBook if not already present.
  ## KeyBook is only set if not already present (to avoid overwriting
  ## keys set by the Identify protocol).
  pool.peerStore[MixPubKeyBook][info.peerId] = info.mixPubKey

  # Add address if not already present.
  # Infinite confidence prevents the libp2p v2.0.0 1h auto-prune from
  # evicting mix node addresses we curated from discovery/static config.
  let existingAddrs = pool.peerStore[AddressBook][info.peerId]
  if info.multiAddr notin existingAddrs:
    pool.peerStore[AddressBook].set(
      info.peerId, existingAddrs & @[info.multiAddr], AddressConfidence.Infinite
    )

  # Only set key if peer has no key yet
  let existingKey = pool.peerStore[KeyBook][info.peerId]
  if existingKey.scheme != Secp256k1:
    pool.peerStore[KeyBook][info.peerId] =
      PublicKey(scheme: Secp256k1, skkey: info.libp2pPubKey)

proc add*(pool: MixNodePool, infos: seq[MixPubInfo]) =
  ## Add multiple mix nodes to the pool.
  for info in infos:
    pool.add(info)

proc remove*(pool: MixNodePool, peerId: PeerId): bool =
  ## Remove a mix node from the pool. Returns true if the node was present.
  pool.peerStore[MixPubKeyBook].del(peerId)
  # Preserve AddressBook/KeyBook entries used by other protocols.

proc get*(pool: MixNodePool, peerId: PeerId): Opt[MixPubInfo] =
  ## The peer as a route hop. None when the pool lacks its keys or an address
  ## that the wire format can encode.
  pool.usablePeer(peerId).expect("the stock pool always answers")

proc peerIds*(pool: MixNodePool): seq[PeerId] =
  ## Get all peer IDs in the mix node pool.
  pool.peerStore[MixPubKeyBook].book.keys.toSeq()

method listPeerIds*(
    pool: MixNodePool
): Result[seq[PeerId], string] {.gcsafe, raises: [].} =
  ok(pool.peerIds())

proc len*(pool: MixNodePool): int =
  ## Get the number of mix nodes in the pool.
  pool.peerStore[MixPubKeyBook].len
