# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

## Mix Node Pool Management
##
## This module provides an abstraction layer for managing mix node information.
## It encapsulates access to the peerStore's MixPubKeyBook, AddressBook, and KeyBook,
## providing a clean interface for the mix protocol to interact with mix node data.

import std/[sequtils, tables]
import results
import libp2p/peerstore
import libp2p/peerid
import libp2p/multiaddress
import libp2p/wire
import libp2p/crypto/crypto
import libp2p/crypto/curve25519
import ./mix_node
import ./multiaddr as mix_multiaddr

export mix_node.MixPubInfo

type MixPubKeyBook* = ref object of PeerBook[Curve25519Key]
  ## Tracks Curve25519 mix public keys per peer. Defined here so the mix
  ## package owns its peer-store extension and libp2p core stays free of
  ## mix-specific types.

type MixAddressClass* {.pure.} = enum
  ## The class of a hop address. The order is the order of preference for the
  ## hop address of one peer.
  Public ## An IP address that the public network routes.
  Relayed ## A circuit relay route through a relay with a public address.
  Private ## Each other IP address that a node can dial.
  Loopback ## An address of the local host. The wildcard address is in this class.

const AllMixAddressClasses* = {MixAddressClass.low .. MixAddressClass.high}

func isSupportedMultiaddr(maddr: MultiAddress): bool =
  ## Returns true if the multiaddress is supported by the mix protocol.
  ## Mix protocol supports IPv4 addresses with TCP or QUIC-v1 transports,
  ## including circuit-relay addresses that use these transports.
  let baseAddr = mix_multiaddr.getBaseTransport(maddr).valueOr:
    return false
  TCP_IP4.match(baseAddr) or QUIC_V1_IP4.match(baseAddr)

proc addressClass*(maddr: MultiAddress): Opt[MixAddressClass] =
  ## Returns the class of `maddr`. A circuit relay route has the class of the
  ## relay address, and `Relayed` replaces `Public` for it. The result is none
  ## for an address that no node can dial, and for an address that is not an
  ## IP transport address with an optional circuit relay suffix.
  let transport = mix_multiaddr.getBaseTransport(maddr).valueOr:
    return Opt.none(MixAddressClass)
  let host = initTAddress(transport).valueOr:
    return Opt.none(MixAddressClass)
  if host.isMulticast() or host.isBroadcast():
    Opt.none(MixAddressClass)
  elif host.isLoopback() or host.isAnyLocal():
    Opt.some(MixAddressClass.Loopback)
  elif not host.isGlobal():
    Opt.some(MixAddressClass.Private)
  elif isCircuitRelayMA(maddr):
    Opt.some(MixAddressClass.Relayed)
  else:
    Opt.some(MixAddressClass.Public)

type MixNodePool* = ref object
  ## Manages mix node public information through the peerStore.
  ## This abstraction allows the mix protocol to interact with mix node data
  ## without directly coupling to peerStore implementation details.
  ##
  ## Future enhancements:
  ## - Peer scoring: Track node reliability, latency, and performance metrics
  ## - Pool maintenance: Automatic pruning of stale/unresponsive nodes
  peerStore: PeerStore
  addressClasses: set[MixAddressClass]
    ## The classes that the hop address of a pool member can have. A different
    ## node dials a hop address, so the classes say which addresses each node of
    ## the network can dial.

proc new*(
    T: typedesc[MixNodePool],
    peerStore: PeerStore,
    addressClasses: set[MixAddressClass] = AllMixAddressClasses,
): T =
  ## Create a new MixNodePool instance backed by the given peerStore.
  T(peerStore: peerStore, addressClasses: addressClasses)

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

proc selectHopAddress(pool: MixNodePool, peerId: PeerId): Opt[MultiAddress] =
  ## Returns the address of the best accepted class that the Sphinx header can
  ## carry. In one class, the last dialed address comes before the AddressBook.
  var candidates: seq[MultiAddress]
  pool.peerStore[LastSeenOutboundBook][peerId].withValue(lastDialed):
    candidates.add(lastDialed)
  candidates.add(pool.peerStore[AddressBook][peerId])

  var best = Opt.none(MultiAddress)
  var bestClass: MixAddressClass
  for candidate in candidates:
    if not isSupportedMultiaddr(candidate):
      continue
    let addrClass = candidate.addressClass().valueOr:
      continue
    if addrClass notin pool.addressClasses:
      continue
    if best.isSome() and addrClass >= bestClass:
      continue
    if mix_multiaddr.multiAddrToBytes(peerId, candidate).isErr():
      continue
    best = Opt.some(candidate)
    bestClass = addrClass
  best

proc get*(pool: MixNodePool, peerId: PeerId): Opt[MixPubInfo] =
  ## Get MixPubInfo for a peer. Returns none if the peer is not in the pool, or
  ## if it has no key or no hop address (see `selectHopAddress`).
  let mixPubKey = pool.peerStore[MixPubKeyBook][peerId]
  if mixPubKey == default(Curve25519Key):
    return Opt.none(MixPubInfo)

  let hopAddr = pool.selectHopAddress(peerId).valueOr:
    return Opt.none(MixPubInfo)

  let pubKey = pool.peerStore[KeyBook][peerId]
  if pubKey.scheme != Secp256k1:
    return Opt.none(MixPubInfo)

  Opt.some(MixPubInfo.init(peerId, hopAddr, mixPubKey, pubKey.skkey))

proc peerIds*(pool: MixNodePool): seq[PeerId] =
  ## Get all peer IDs in the mix node pool.
  pool.peerStore[MixPubKeyBook].book.keys.toSeq()

proc len*(pool: MixNodePool): int =
  ## Get the number of mix nodes in the pool.
  pool.peerStore[MixPubKeyBook].len
