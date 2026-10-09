# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Logos

{.used.}

import chronos, results
import std/sequtils
import libp2p/[builders, switch, multiaddress, peerid]
import libp2p/crypto/[crypto, secp]
import libp2p/protocols/protocol
import libp2p/stream/connection
import libp2p_mix
import libp2p_mix/[mix_protocol, cover_traffic]
import ../tools/[crypto, unittest]

type
  Counter = ref object
    received: int

  CoverCounter = ref object of CoverTraffic
    received: int

method start(ct: CoverCounter) {.async: (raises: [CancelledError]).} =
  discard

method stop(ct: CoverCounter) {.async: (raises: []).} =
  discard

method onCoverReceived(ct: CoverCounter) {.gcsafe, raises: [].} =
  inc ct.received

proc makeSwitch(info: MixNodeInfo, rng: Rng): Switch =
  SwitchBuilder
    .new()
    .withRng(rng)
    .withPrivateKey(PrivateKey(scheme: Secp256k1, skkey: info.libp2pPrivKey))
    .withAddress(MultiAddress.init("/ip4/127.0.0.1/tcp/0").tryGet())
    .withTcpTransport()
    .withMplex()
    .withNoise()
    .build()

proc receiver(counter: Counter): LPProtocol =
  LPProtocol.new(
    codecs = @["/mix/test/roles/1.0.0"],
    handler = proc(
        conn: Connection, proto: string
    ) {.async: (raises: [CancelledError]).} =
      try:
        let payload = await conn.readLp(1024)
        doAssert payload == @[1.byte, 2, 3]
        inc counter.received
      except LPStreamError:
        discard
      finally:
        await conn.close()
    ,
  )

proc send(proto: MixProtocol, dest: MixDestination): Future[bool] {.async.} =
  let conn = proto.toConnection(dest, "/mix/test/roles/1.0.0").tryGet()
  defer:
    await conn.close()
  try:
    await conn.writeLp(@[1.byte, 2, 3])
    return true
  except LPStreamError:
    return false

proc defaultExitDelivery() {.async.} =
  let testRng = rng()
  var infos = MixNodeInfo.generateRandomMany(5, testRng)
  var switches: seq[Switch]
  var protos: seq[MixProtocol]
  let cover = CoverCounter(slotPool: SlotPool.new(100))
  let local = Counter()
  let external = Counter()
  for i in 0 ..< infos.len:
    let sw = makeSwitch(infos[i], testRng)
    let ct =
      if i == 4:
        Opt.some(CoverTraffic(cover))
      else:
        Opt.none(CoverTraffic)
    let proto = MixProtocol.new(infos[i], sw, coverTraffic = ct)
    sw.mount(proto)
    if i == 4:
      sw.mount(receiver(local))
    switches.add(sw)
    protos.add(proto)
  defer:
    await switches.mapIt(it.stop()).allFutures()
  let dest = makeSwitch(MixNodeInfo.generateRandom(0, testRng), testRng)
  dest.mount(receiver(external))
  defer:
    await dest.stop()
  await switches.mapIt(it.start()).allFutures()
  await dest.start()
  for i in 0 ..< infos.len:
    infos[i].multiAddr = switches[i].peerInfo.addrs[0]
    protos[i].setLocalMultiAddr(infos[i].multiAddr).expect("bound address")
  for i in 0 ..< infos.len:
    for j in 0 ..< infos.len:
      if i == j:
        continue
      protos[i].nodePool.add(infos[j].toMixPubInfo())

  let localDest = MixDestination.exitNode(infos[4].peerId)
  let externalDest =
    MixDestination.forwardToAddr(dest.peerInfo.peerId, dest.peerInfo.addrs[0])
  doAssert await send(protos[0], localDest)
  doAssert await send(protos[0], externalDest)
  checkUntilTimeout:
    local.received == 1
    external.received == 1
  doAssert local.received == 1
  doAssert external.received == 1

  let packet = (await protos[4].buildCoverPacket()).expect("build cover loop")
  (
    await protos[4].sendCoverPacket(
      packet.firstHopPeerId, packet.firstHopAddr, packet.packet
    )
  ).expect("send cover loop")
  checkUntilTimeout:
    cover.received == 1
  echo "PASS: default local/external exit delivery and cover loop received"

suite "Default exit delivery":
  asyncTest "default nodes deliver locally and externally and consume cover loops":
    await defaultExitDelivery()
