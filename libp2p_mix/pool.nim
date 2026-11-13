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
import libp2p/peeraddrpolicy
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

func hopHost(maddr: MultiAddress): Opt[TransportAddress] =
  ## Returns the IP address and the port that a node dials to reach the hop
  ## address `maddr`, which for a circuit relay route is the relay's address.
  ## The result is none when the mix protocol does not support `maddr`.
  ## Mix protocol supports IPv4 addresses with TCP or QUIC-v1 transports,
  ## including circuit-relay addresses that use these transports.
  ## It is also none for port 0 and for a multicast or broadcast address, since
  ## no node can dial these.
  ## The wildcard address `0.0.0.0` is left to the policy, because local test nodes
  ## announce it and `publicHopAddressPolicy` refuses it.
  let transport = mix_multiaddr.getBaseTransport(maddr).valueOr:
    return Opt.none(TransportAddress)
  if not (TCP_IP4.match(transport) or QUIC_V1_IP4.match(transport)):
    return Opt.none(TransportAddress)
  let host = initTAddress(transport).valueOr:
    return Opt.none(TransportAddress)
  if host.port == Port(0) or host.isMulticast() or host.isBroadcast():
    return Opt.none(TransportAddress)
  Opt.some(host)

const publicHopAddressPolicy* = proc(maddr: MultiAddress): bool {.gcsafe, raises: [].} =
  ## Accepts a hop address that any node on the public network can dial, that is,
  ## an IPv4 address that the public network routes.
  ## A circuit relay route must go through a relay with such an address, while
  ## libp2p's `publicRoutableAddressPolicy` accepts a route through any relay.
  let host = hopHost(maddr).valueOr:
    return false
  host.isGlobal()

type MixNodePool* = ref object
  ## Manages mix node public information through the peerStore.
  ## This abstraction allows the mix protocol to interact with mix node data
  ## without directly coupling to peerStore implementation details.
  ##
  ## Future enhancements:
  ## - Peer scoring: Track node reliability, latency, and performance metrics
  ## - Pool maintenance: Automatic pruning of stale/unresponsive nodes
  peerStore: PeerStore
  hopAddressPolicy: PeerAddressPolicy
    ## Decides which addresses of a pool member can be its hop address, that is, the
    ## address that the previous node on a path dials.

proc new*(
    T: typedesc[MixNodePool],
    peerStore: PeerStore,
    hopAddressPolicy: PeerAddressPolicy = defaultAddressPolicy,
): T {.raises: [].} =
  ## Create a new MixNodePool instance backed by the given peerStore.
  ## A nil `hopAddressPolicy` is replaced by the default policy, which accepts any
  ## address, so the pool can call the policy without a nil check.
  let policy = if hopAddressPolicy.isNil(): defaultAddressPolicy else: hopAddressPolicy
  T(peerStore: peerStore, hopAddressPolicy: policy)

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

type MixHop* = object ## A pool member that a path can use.
  info*: MixPubInfo
  addrBytes*: seq[byte] ## Its hop address, encoded for the Sphinx header.

proc hopAddressBytes(
    pool: MixNodePool, peerId: PeerId, maddr: MultiAddress
): Opt[seq[byte]] =
  ## Returns `maddr` encoded for the Sphinx header, or none if a path cannot use it
  ## as the hop address of `peerId`.
  if hopHost(maddr).isNone() or not pool.hopAddressPolicy(maddr):
    return Opt.none(seq[byte])
  mix_multiaddr.multiAddrToBytes(peerId, maddr).optValue()

type HopAddress = tuple[multiAddr: MultiAddress, addrBytes: seq[byte]]
  ## A hop address together with its encoding for the Sphinx header.

proc selectHopAddress(pool: MixNodePool, peerId: PeerId): Opt[HopAddress] =
  ## Returns the first address of `peerId` that a path can use as its hop address.
  ## Direct addresses are tried before circuit relay routes, because a relayed
  ## connection has a time limit and a data limit, and a write past the data limit
  ## silently loses the packet.
  ## Within each group, the last dialed address is tried before the AddressBook.
  let lastDialedAddr = pool.peerStore[LastSeenOutboundBook][peerId]
  let storedAddrs = pool.peerStore[AddressBook][peerId]
  for relayed in [false, true]:
    lastDialedAddr.withValue(lastDialed):
      if isCircuitRelayMA(lastDialed) == relayed:
        pool.hopAddressBytes(peerId, lastDialed).withValue(addrBytes):
          return Opt.some((lastDialed, addrBytes))
    for maddr in storedAddrs:
      if isCircuitRelayMA(maddr) == relayed:
        pool.hopAddressBytes(peerId, maddr).withValue(addrBytes):
          return Opt.some((maddr, addrBytes))
  Opt.none(HopAddress)

proc getHop*(pool: MixNodePool, peerId: PeerId): Opt[MixHop] {.raises: [].} =
  ## Get MixPubInfo for a peer together with its hop address already encoded for the
  ## Sphinx header, so that a path builder does not have to encode it again.
  ## Returns none if the peer is not in the pool, or has no key or no hop address.
  let mixPubKey = pool.peerStore[MixPubKeyBook][peerId]
  if mixPubKey == default(Curve25519Key):
    return Opt.none(MixHop)

  let pubKey = pool.peerStore[KeyBook][peerId]
  if pubKey.scheme != Secp256k1:
    return Opt.none(MixHop)

  let hopAddr = pool.selectHopAddress(peerId).valueOr:
    return Opt.none(MixHop)

  Opt.some(
    MixHop(
      info: MixPubInfo.init(peerId, hopAddr.multiAddr, mixPubKey, pubKey.skkey),
      addrBytes: hopAddr.addrBytes,
    )
  )

proc get*(pool: MixNodePool, peerId: PeerId): Opt[MixPubInfo] {.raises: [].} =
  ## Get MixPubInfo for a peer.
  ## Returns none if the peer is not in the pool, or has no key or no hop address.
  let hop = pool.getHop(peerId).valueOr:
    return Opt.none(MixPubInfo)
  Opt.some(hop.info)

proc peerIds*(pool: MixNodePool): seq[PeerId] =
  ## Get all peer IDs in the mix node pool.
  pool.peerStore[MixPubKeyBook].book.keys.toSeq()

proc len*(pool: MixNodePool): int =
  ## Get the number of mix nodes in the pool.
  pool.peerStore[MixPubKeyBook].len
