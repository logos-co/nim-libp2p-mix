# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.used.}

import results, sequtils
import
  libp2p/[crypto/crypto, crypto/secp, multiaddress, peeraddrpolicy, peerid, peerstore]
import libp2p_mix/[mix_node, multiaddr, pool]
import ./tools/unittest
import ./tools/crypto
import ./utils

suite "MixNodePool Tests":
  var
    peerStore {.threadvar.}: PeerStore
    pool {.threadvar.}: MixNodePool
    mixNodes {.threadvar.}: seq[MixNodeInfo]

  setup:
    peerStore = PeerStore.new()
    pool = MixNodePool.new(peerStore)
    mixNodes = MixNodeInfo.generateRandomMany(5, rng())

  test "new creates empty pool":
    check pool.len == 0

  test "add stores mix node info":
    let pubInfo = mixNodes[0].toMixPubInfo()

    pool.add(pubInfo)

    check:
      pool.len == 1
      pool.get(pubInfo.peerId).isSome
      pool.get(pubInfo.peerId).get() == pubInfo

  test "add stores all required data in peerStore":
    let pubInfo = mixNodes[0].toMixPubInfo()

    pool.add(pubInfo)

    check:
      peerStore[MixPubKeyBook][pubInfo.peerId] == pubInfo.mixPubKey
      peerStore[AddressBook][pubInfo.peerId] == @[pubInfo.multiAddr]
      peerStore[KeyBook][pubInfo.peerId].scheme == Secp256k1
      peerStore[KeyBook][pubInfo.peerId].skkey == pubInfo.libp2pPubKey

  test "bulk add stores multiple mix nodes":
    let pubInfos = mixNodes.mapIt(it.toMixPubInfo())

    pool.add(pubInfos)

    check pool.len == mixNodes.len
    for pubInfo in pubInfos:
      check pool.get(pubInfo.peerId).isSome
      check pool.get(pubInfo.peerId).get() == pubInfo

  test "bulk add with empty seq is no-op":
    pool.add(newSeq[MixPubInfo]())
    check pool.len == 0

  test "remove deletes from pool":
    let pubInfo = mixNodes[0].toMixPubInfo()

    pool.add(pubInfo)
    check pool.len == 1

    let removed = pool.remove(pubInfo.peerId)

    check:
      removed == true
      pool.len == 0
      pool.get(pubInfo.peerId).isNone

  test "remove returns false for non-existent peer":
    let peerId = PeerId.random(rng()).expect("could not generate peerId")
    check pool.remove(peerId) == false

  test "get returns none for non-existent peer":
    let peerId = PeerId.random(rng()).expect("could not generate peerId")
    check pool.get(peerId).isNone

  test "get returns none when address is missing":
    let pubInfo = mixNodes[0].toMixPubInfo()

    # Manually add only the mix key, not the address
    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey

    check pool.get(pubInfo.peerId).isNone

  test "get returns none when key scheme is not Secp256k1":
    let pubInfo = mixNodes[0].toMixPubInfo()

    # Manually add with wrong key scheme
    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[AddressBook][pubInfo.peerId] = @[pubInfo.multiAddr]
    # KeyBook is not set, so scheme defaults to something other than Secp256k1

    check pool.get(pubInfo.peerId).isNone

  test "get filters for supported addresses (IPv4 with TCP or QUIC-v1)":
    let pubInfo = mixNodes[0].toMixPubInfo()
    let relayPeerId = PeerId.random(rng()).expect("could not generate relay peerId")
    let ipv6Addr =
      MultiAddress.init("/ip6/::1/tcp/4242").expect("could not create multiaddr")
    let udpAddr =
      MultiAddress.init("/ip4/127.0.0.1/udp/4242").expect("could not create multiaddr")
    let tcpAddr =
      MultiAddress.init("/ip4/127.0.0.1/tcp/4243").expect("could not create multiaddr")
    let quicAddr = MultiAddress.init("/ip4/127.0.0.1/udp/4244/quic-v1").expect(
        "could not create multiaddr"
      )
    # Circuit-relay addresses
    let tcpCircuitAddr = MultiAddress
      .init("/ip4/127.0.0.1/tcp/4245/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")
    let quicCircuitAddr = MultiAddress
      .init("/ip4/127.0.0.1/udp/4246/quic-v1/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")
    let ipv6CircuitAddr = MultiAddress
      .init("/ip6/::1/tcp/4247/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)

    # Only IPv6 - should return none
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6Addr]
    check pool.get(pubInfo.peerId).isNone

    # Only UDP (without QUIC-v1) - should return none
    peerStore[AddressBook][pubInfo.peerId] = @[udpAddr]
    check pool.get(pubInfo.peerId).isNone

    # IPv6 and UDP first, then TCP - should return TCP
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6Addr, udpAddr, tcpAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == tcpAddr

    # UDP first, then QUIC-v1 - should return QUIC-v1
    peerStore[AddressBook][pubInfo.peerId] = @[udpAddr, quicAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == quicAddr

    # TCP and QUIC-v1 both available - should return first match (TCP)
    peerStore[AddressBook][pubInfo.peerId] = @[tcpAddr, quicAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == tcpAddr

    # TCP circuit-relay - should be supported
    peerStore[AddressBook][pubInfo.peerId] = @[tcpCircuitAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == tcpCircuitAddr

    # QUIC-v1 circuit-relay - should be supported
    peerStore[AddressBook][pubInfo.peerId] = @[quicCircuitAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == quicCircuitAddr

    # IPv6 circuit-relay - should return none (unsupported transport)
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6CircuitAddr]
    check pool.get(pubInfo.peerId).isNone

    # Mixed: unsupported circuit-relay first, then supported - should return supported
    peerStore[AddressBook][pubInfo.peerId] = @[ipv6CircuitAddr, tcpCircuitAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == tcpCircuitAddr

  test "peerIds returns all peer IDs":
    for i in 0 ..< mixNodes.len:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.add(pubInfo)

    let peerIds = pool.peerIds()

    check peerIds.len == mixNodes.len

    for i in 0 ..< mixNodes.len:
      let pubInfo = mixNodes[i].toMixPubInfo()
      check pubInfo.peerId in peerIds

  test "len returns correct count":
    check pool.len == 0

    for i in 0 ..< 3:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.add(pubInfo)
      check pool.len == i + 1

  test "get prefers LastSeenOutboundBook over AddressBook":
    let pubInfo = mixNodes[0].toMixPubInfo()
    let addressBookAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4242").expect(
        "could not create multiaddr"
      )
    let lastSeenAddr =
      MultiAddress.init("/ip4/10.0.0.1/tcp/4243").expect("could not create multiaddr")
    let lastSeenIpv6Addr =
      MultiAddress.init("/ip6/::1/tcp/4244").expect("could not create multiaddr")

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)
    peerStore[AddressBook][pubInfo.peerId] = @[addressBookAddr]

    # When LastSeenOutboundBook has a supported address, prefer it
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(lastSeenAddr)
    check pool.get(pubInfo.peerId).get().multiAddr == lastSeenAddr

    # When LastSeenOutboundBook has unsupported address (IPv6), fall back to AddressBook
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(lastSeenIpv6Addr)
    check pool.get(pubInfo.peerId).get().multiAddr == addressBookAddr

    # When LastSeenOutboundBook is empty, fall back to AddressBook
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.none(MultiAddress)
    check pool.get(pubInfo.peerId).get().multiAddr == addressBookAddr

  test "get returns the first address that the policy accepts":
    ## `get` tries the addresses in AddressBook order, and the default policy accepts
    ## any address.
    let pubInfo = mixNodes[0].toMixPubInfo()
    let publicPool = MixNodePool.new(peerStore, publicHopAddressPolicy)
    let publicAddr =
      MultiAddress.init("/ip4/8.8.8.8/tcp/4242").expect("could not create multiaddr")
    let privateAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4244").expect(
        "could not create multiaddr"
      )
    let loopbackAddr =
      MultiAddress.init("/ip4/127.0.0.1/tcp/4245").expect("could not create multiaddr")

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)

    peerStore[AddressBook][pubInfo.peerId] = @[loopbackAddr, privateAddr, publicAddr]
    check:
      pool.get(pubInfo.peerId).get().multiAddr == loopbackAddr
      publicPool.get(pubInfo.peerId).get().multiAddr == publicAddr

    peerStore[AddressBook][pubInfo.peerId] = @[publicAddr, privateAddr, loopbackAddr]
    check:
      pool.get(pubInfo.peerId).get().multiAddr == publicAddr
      publicPool.get(pubInfo.peerId).get().multiAddr == publicAddr

  test "get returns the last dialed address when the policy accepts it":
    ## The last dialed address is correct for this node. A node of another
    ## network cannot dial it when it is private.
    let pubInfo = mixNodes[0].toMixPubInfo()
    let publicPool = MixNodePool.new(peerStore, publicHopAddressPolicy)
    let publicAddr =
      MultiAddress.init("/ip4/8.8.8.8/tcp/4242").expect("could not create multiaddr")
    let otherPublicAddr =
      MultiAddress.init("/ip4/1.1.1.1/tcp/4243").expect("could not create multiaddr")
    let privateAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4244").expect(
        "could not create multiaddr"
      )

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)
    peerStore[AddressBook][pubInfo.peerId] = @[publicAddr]

    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(privateAddr)
    check:
      pool.get(pubInfo.peerId).get().multiAddr == privateAddr
      publicPool.get(pubInfo.peerId).get().multiAddr == publicAddr

    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(otherPublicAddr)
    check:
      pool.get(pubInfo.peerId).get().multiAddr == otherPublicAddr
      publicPool.get(pubInfo.peerId).get().multiAddr == otherPublicAddr

  test "get returns none for a peer with no address that the policy accepts":
    let pubInfo = mixNodes[0].toMixPubInfo()
    let publicPool = MixNodePool.new(peerStore, publicHopAddressPolicy)
    let publicAddr =
      MultiAddress.init("/ip4/8.8.8.8/tcp/4242").expect("could not create multiaddr")
    let privateAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4244").expect(
        "could not create multiaddr"
      )
    let loopbackAddr =
      MultiAddress.init("/ip4/127.0.0.1/tcp/4245").expect("could not create multiaddr")

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)

    peerStore[AddressBook][pubInfo.peerId] = @[loopbackAddr, privateAddr]
    check:
      publicPool.get(pubInfo.peerId).isNone
      pool.get(pubInfo.peerId).isSome

    peerStore[AddressBook][pubInfo.peerId] = @[loopbackAddr, privateAddr, publicAddr]
    check publicPool.get(pubInfo.peerId).get().multiAddr == publicAddr

  test "get with publicHopAddressPolicy accepts a relay route only through a public relay":
    ## The previous hop dials the relay. A relay with a private or loopback
    ## address is not a public route.
    let pubInfo = mixNodes[0].toMixPubInfo()
    let publicPool = MixNodePool.new(peerStore, publicHopAddressPolicy)
    let relayPeerId = PeerId.random(rng()).expect("could not generate relay peerId")
    let relaySuffix = "/p2p/" & $relayPeerId & "/p2p-circuit"
    let publicRelayAddr = MultiAddress
      .init("/ip4/8.8.8.8/tcp/4242" & relaySuffix)
      .expect("could not create multiaddr")
    let privateRelayAddr = MultiAddress
      .init("/ip4/192.168.1.1/tcp/4243" & relaySuffix)
      .expect("could not create multiaddr")
    let loopbackRelayAddr = MultiAddress
      .init("/ip4/127.0.0.1/tcp/4244" & relaySuffix)
      .expect("could not create multiaddr")

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)

    peerStore[AddressBook][pubInfo.peerId] = @[loopbackRelayAddr, privateRelayAddr]
    check:
      publicPool.get(pubInfo.peerId).isNone
      pool.get(pubInfo.peerId).get().multiAddr == loopbackRelayAddr

    peerStore[AddressBook][pubInfo.peerId] =
      @[loopbackRelayAddr, privateRelayAddr, publicRelayAddr]
    check publicPool.get(pubInfo.peerId).get().multiAddr == publicRelayAddr

  test "publicHopAddressPolicy accepts the IPv4 addresses that the public network routes":
    let relayPeerId = PeerId.random(rng()).expect("could not generate relay peerId")
    let relaySuffix = "/p2p/" & $relayPeerId & "/p2p-circuit"
    proc accepted(address: string): bool =
      publicHopAddressPolicy(
        MultiAddress.init(address).expect("could not create multiaddr")
      )

    check:
      accepted("/ip4/8.8.8.8/tcp/4242")
      accepted("/ip4/8.8.8.8/udp/4242/quic-v1")
      accepted("/ip4/8.8.8.8/tcp/4242" & relaySuffix)
      accepted("/ip4/8.8.8.8/udp/4242/quic-v1" & relaySuffix)
      not accepted("/ip4/192.168.1.1/tcp/4242")
      not accepted("/ip4/10.0.0.1/tcp/4242")
      not accepted("/ip4/100.64.0.1/tcp/4242")
      not accepted("/ip4/169.254.0.1/tcp/4242")
      not accepted("/ip4/192.168.1.1/tcp/4242" & relaySuffix)
      not accepted("/ip4/127.0.0.1/tcp/4242")
      not accepted("/ip6/::1/tcp/4242")
      not accepted("/ip6/2001:4860:4860::8888/tcp/4242")
      not accepted("/ip4/0.0.0.0/tcp/4242")
      not accepted("/ip4/127.0.0.1/tcp/4242" & relaySuffix)
      not accepted("/ip4/224.0.0.1/tcp/4242")
      not accepted("/ip4/255.255.255.255/tcp/4242")
      not accepted("/dns4/example.com/tcp/4242")
      not accepted("/ip4/8.8.8.8")
      not accepted("/ip4/8.8.8.8/tcp/0")

  test "get with libp2p's publicRoutableAddressPolicy accepts a private relay":
    ## libp2p's `publicRoutableAddressPolicy` accepts a route through any relay.
    let pubInfo = mixNodes[0].toMixPubInfo()
    let libp2pPool = MixNodePool.new(peerStore, publicRoutableAddressPolicy)
    let publicPool = MixNodePool.new(peerStore, publicHopAddressPolicy)
    let relayPeerId = PeerId.random(rng()).expect("could not generate relay peerId")
    let privateRelayAddr = MultiAddress
      .init("/ip4/192.168.1.1/tcp/4242/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")
    let privateAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4244").expect(
        "could not create multiaddr"
      )

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)

    peerStore[AddressBook][pubInfo.peerId] = @[privateAddr, privateRelayAddr]
    check:
      libp2pPool.get(pubInfo.peerId).get().multiAddr == privateRelayAddr
      publicPool.get(pubInfo.peerId).isNone

  test "a nil policy accepts any address":
    ## The pool calls the policy without a nil check, so it has to replace a nil policy.
    let pubInfo = mixNodes[0].toMixPubInfo()
    let nilPool = MixNodePool.new(peerStore, nil)
    let privateAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4244").expect(
        "could not create multiaddr"
      )

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)
    peerStore[AddressBook][pubInfo.peerId] = @[privateAddr]

    check nilPool.get(pubInfo.peerId).get().multiAddr == privateAddr

  test "get returns a direct address before a circuit relay route":
    ## A write past the data limit of a relayed connection loses the packet.
    let pubInfo = mixNodes[0].toMixPubInfo()
    let publicPool = MixNodePool.new(peerStore, publicHopAddressPolicy)
    let relayPeerId = PeerId.random(rng()).expect("could not generate relay peerId")
    let relayedAddr = MultiAddress
      .init("/ip4/8.8.8.8/tcp/4242/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")
    let otherRelayedAddr = MultiAddress
      .init("/ip4/8.8.4.4/tcp/4244/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")
    let publicAddr =
      MultiAddress.init("/ip4/1.1.1.1/tcp/4243").expect("could not create multiaddr")

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)

    peerStore[AddressBook][pubInfo.peerId] = @[relayedAddr, publicAddr]
    check:
      pool.get(pubInfo.peerId).get().multiAddr == publicAddr
      publicPool.get(pubInfo.peerId).get().multiAddr == publicAddr

    peerStore[AddressBook][pubInfo.peerId] = @[relayedAddr]
    check:
      pool.get(pubInfo.peerId).get().multiAddr == relayedAddr
      publicPool.get(pubInfo.peerId).get().multiAddr == relayedAddr

    # A last dialed relay route comes after a direct address from the AddressBook.
    peerStore[LastSeenOutboundBook][pubInfo.peerId] = Opt.some(otherRelayedAddr)
    peerStore[AddressBook][pubInfo.peerId] = @[relayedAddr, publicAddr]
    check:
      pool.get(pubInfo.peerId).get().multiAddr == publicAddr
      publicPool.get(pubInfo.peerId).get().multiAddr == publicAddr

    # But it comes before a relay route from the AddressBook.
    peerStore[AddressBook][pubInfo.peerId] = @[relayedAddr]
    check:
      pool.get(pubInfo.peerId).get().multiAddr == otherRelayedAddr
      publicPool.get(pubInfo.peerId).get().multiAddr == otherRelayedAddr

  test "get skips an address that no node can dial":
    ## The default policy accepts these addresses.
    let pubInfo = mixNodes[0].toMixPubInfo()
    let multicastAddr =
      MultiAddress.init("/ip4/224.0.0.1/tcp/4242").expect("could not create multiaddr")
    let broadcastAddr = MultiAddress.init("/ip4/255.255.255.255/tcp/4243").expect(
        "could not create multiaddr"
      )
    let portZeroAddr =
      MultiAddress.init("/ip4/192.168.1.1/tcp/0").expect("could not create multiaddr")
    let privateAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4244").expect(
        "could not create multiaddr"
      )

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)

    peerStore[AddressBook][pubInfo.peerId] =
      @[multicastAddr, broadcastAddr, portZeroAddr]
    check pool.get(pubInfo.peerId).isNone

    peerStore[AddressBook][pubInfo.peerId] =
      @[multicastAddr, broadcastAddr, portZeroAddr, privateAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == privateAddr

  test "getHop returns the hop address encoded for the Sphinx header":
    ## A path builder uses these bytes instead of encoding the address again.
    let pubInfo = mixNodes[0].toMixPubInfo()
    let publicAddr =
      MultiAddress.init("/ip4/8.8.8.8/tcp/4242").expect("could not create multiaddr")
    let privateAddr = MultiAddress.init("/ip4/192.168.1.1/tcp/4244").expect(
        "could not create multiaddr"
      )

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)
    peerStore[AddressBook][pubInfo.peerId] = @[privateAddr, publicAddr]

    let hop = pool.getHop(pubInfo.peerId).get()
    check:
      hop.info.multiAddr == privateAddr
      hop.addrBytes == multiAddrToBytes(pubInfo.peerId, privateAddr).get()
      hop.info == pool.get(pubInfo.peerId).get()

  test "get skips an address that the Sphinx header cannot carry":
    ## A relay route through an Ed25519 relay has a supported transport, and
    ## the header has no encoding for the ID of the relay.
    let pubInfo = mixNodes[0].toMixPubInfo()
    let relayKey = PrivateKey.random(PKScheme.Ed25519, rng()).expect("relay key")
    let relayPeerId = PeerId.init(relayKey).expect("relay peerId")
    let relayedAddr = MultiAddress
      .init("/ip4/8.8.8.8/tcp/4242/p2p/" & $relayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")
    let otherRelayPeerId =
      PeerId.random(rng()).expect("could not generate relay peerId")
    let otherRelayedAddr = MultiAddress
      .init("/ip4/8.8.4.4/tcp/4243/p2p/" & $otherRelayPeerId & "/p2p-circuit")
      .expect("could not create multiaddr")

    peerStore[MixPubKeyBook][pubInfo.peerId] = pubInfo.mixPubKey
    peerStore[KeyBook][pubInfo.peerId] =
      PublicKey(scheme: Secp256k1, skkey: pubInfo.libp2pPubKey)

    peerStore[AddressBook][pubInfo.peerId] = @[relayedAddr]
    check pool.get(pubInfo.peerId).isNone

    peerStore[AddressBook][pubInfo.peerId] = @[relayedAddr, otherRelayedAddr]
    check pool.get(pubInfo.peerId).get().multiAddr == otherRelayedAddr

  test "multiple operations sequence":
    # Add 3 nodes
    for i in 0 ..< 3:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.add(pubInfo)

    check pool.len == 3

    # Remove middle node
    let middlePubInfo = mixNodes[1].toMixPubInfo()
    discard pool.remove(middlePubInfo.peerId)

    check:
      pool.len == 2
      pool.get(middlePubInfo.peerId).isNone

    # Add two more nodes
    for i in 3 ..< 5:
      let pubInfo = mixNodes[i].toMixPubInfo()
      pool.add(pubInfo)

    check pool.len == 4
