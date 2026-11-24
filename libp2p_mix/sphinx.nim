# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import results
import stew/ctops
import nimcrypto/utils # burnMem
import ./[crypto, curve25519, delay, key_rotation, lioness, serialization, tag_manager]
import libp2p/crypto/crypto

const PathLength* = DefaultPathLength # Compatibility alias for the default L

proc validatePathInputs(
    publicKeys: openArray[FieldElement], delay: openArray[Delay], hops: openArray[Hop]
): Result[void, string] =
  if publicKeys.len < MinPathLength or publicKeys.len > MaxPathLength:
    return
      err("path length must be between " & $MinPathLength & " and " & $MaxPathLength)
  if delay.len != publicKeys.len or hops.len != publicKeys.len:
    return err("path keys, delays, and hops must have equal lengths")
  ok()

const
  # KDF domain-separation labels used in per-hop key derivation.
  AesKeyLabel = "aes_key" # header (beta) AES key
  IvLabel = "iv" # header (beta) AES IV
  MacKeyLabel = "mac_key" # per-hop MAC key
  PayloadEncKeyLabel = "payload_enc_key" # LIP-183 §4.3: payload delta_key domain

type ProcessingStatus* = enum
  Exit
  Intermediate
  Reply
  Duplicate
  ReplayCacheFull
  InvalidMAC

proc computeAlpha(
    publicKeys: openArray[FieldElement]
): Result[(seq[byte], seq[seq[byte]]), string] =
  ## Compute alpha, an ephemeral public value. Each mix node uses its private key and 
  ## alpha to derive a shared session key for that hop. 
  ## This session key is used to decrypt and process one layer of the packet.

  if publicKeys.len == 0:
    return err("No public keys provided")

  var
    s: seq[seq[byte]] = newSeq[seq[byte]](publicKeys.len)
    alpha_0: seq[byte]
    alpha: FieldElement
    secret: FieldElement
    blinders: seq[FieldElement] = @[]
  # The blinders include the ephemeral scalar, so they are wiped too. The
  # secrets in s are moved out on success and wiped on every early return.
  defer:
    burnMem(secret)
    for blinder in blinders.mitems:
      burnMem(blinder)
    for hopSecret in s.mitems:
      burnMem(hopSecret)

  var x = generateRandomFieldElement().valueOr:
    return err("Generate field element error: " & error)

  blinders.add(x)
  burnMem(x)

  for i in 0 ..< publicKeys.len:
    if publicKeys[i].len != FieldElementSize:
      return err("Invalid public key size: " & $i)

    # Compute alpha, shared secret, and blinder
    var scalars = [blinders[i]]
    defer:
      burnMem(scalars)
    if i == 0:
      alpha = multiplyBasePointWithScalars(scalars).valueOr:
        return err("Multiply base point with scalars error: " & error)

      alpha_0 = fieldElementToBytes(alpha)
    else:
      alpha = multiplyPointWithScalars(alpha, scalars)

    # TODO: Optimize point multiplication by multiplying scalars first
    secret = multiplyPointWithScalars(publicKeys[i], blinders)
    var
      secretBytes = fieldElementToBytes(secret)
      blinderInput = fieldElementToBytes(alpha) & secretBytes
      blinderHash = sha256_hash(blinderInput)
    defer:
      burnMem(secretBytes)
      burnMem(blinderInput)
      burnMem(blinderHash)

    var blinder = bytesToFieldElement(blinderHash).valueOr:
      return err("Error in bytes to field element conversion: " & error)

    blinders.add(blinder)
    burnMem(blinder)

    s[i] = secretBytes

  return ok((alpha_0, move(s)))

proc deriveKeyMaterial(keyName: string, s: seq[byte]): seq[byte] =
  @(keyName.toOpenArrayByte(0, keyName.high)) & s

proc deriveKey(label: string, sBytes: seq[byte]): seq[byte] {.raises: [].} =
  ## KDF over label and the shared secret, wiping the input that holds the secret.
  var material = deriveKeyMaterial(label, sBytes)
  defer:
    burnMem(material)
  material.kdf()

proc isZeros(data: seq[byte], startIdx: int, endIdx: int): bool =
  doAssert 0 <= startIdx and endIdx < data.len and startIdx <= endIdx
  for i in startIdx .. endIdx:
    if data[i] != 0:
      return false
  return true

proc computeFillerStrings(s: seq[seq[byte]]): Result[seq[byte], string] =
  var filler: seq[byte] = @[] # Start with an empty filler string

  for i in 1 ..< s.len:
    # Derive AES key and IV
    var
      aes_key = deriveKey(AesKeyLabel, s[i - 1])
      iv = deriveKey(IvLabel, s[i - 1])
    defer:
      burnMem(aes_key)
      burnMem(iv)

    # Compute filler string
    let
      fillerLength = (t + 1) * k
      zeroPadding = newSeq[byte](fillerLength)

    filler = aes_ctr_start_index(
      aes_key, iv, filler & zeroPadding, (((t + 1) * (MaxPathLength - i)) + t + 2) * k
    )

  return ok(filler)

proc computeBetaGamma(
    s: seq[seq[byte]],
    hops: openArray[Hop],
    delay: openArray[Delay],
    destHop: Hop,
    id: SURBIdentifier,
    rng: Rng = nil,
): Result[tuple[beta: seq[byte], gamma: seq[byte]], string] =
  ## Calculates the following elements:
  ## - Beta: The nested encrypted routing information. It encodes the next hop address, the forwarding delay, integrity check Gamma for the next hop, and the Beta for subsequent hops.
  ## - Gamma: A message authentication code computed over Beta using the session key derived from Alpha. It ensures header integrity at each hop.
  let sLen = s.len
  var
    beta: seq[byte]
    gamma: seq[byte]

  # Compute filler strings
  let filler = computeFillerStrings(s).valueOr:
    return err("Error in filler generation: " & error)

  for i in countdown(sLen - 1, 0):
    # Derive AES key, MAC key, and IV
    var
      beta_aes_key = deriveKey(AesKeyLabel, s[i])
      mac_key = deriveKey(MacKeyLabel, s[i])
      beta_iv = deriveKey(IvLabel, s[i])
    defer:
      burnMem(beta_aes_key)
      burnMem(mac_key)
      burnMem(beta_iv)

    # Compute Beta and Gamma
    if i == sLen - 1:
      let destBytes = destHop.serialize()
      let delayBytes = delay[i].toBytes()
      let paddingLength = (((t + 1) * (MaxPathLength - sLen)) + 1) * k
      var padding = newSeq[byte](paddingLength)
      # Keep the fixed k-byte terminal marker. Randomize unused hop capacity
      # so the exit cannot locate the filler boundary by counting zero bytes.
      if paddingLength > k:
        let paddingRng =
          if rng.isNil:
            newRng()
          else:
            rng
        if paddingRng.isNil:
          return err("Failed to create Rng with system randomness")
        paddingRng.generate(padding.toOpenArray(k, padding.high))
      let destPadding = destBytes & delayBytes & @id & padding

      let aes = aes_ctr(beta_aes_key, beta_iv, destPadding)

      beta = aes & filler
    else:
      let routingInfo = RoutingInfo.init(
        hops[i + 1],
        delay[i],
        gamma,
        beta[0 .. (((MaxPathLength * (t + 1)) - t) * k) - 1],
      )

      let serializedRoutingInfo = routingInfo.serialize()

      beta = aes_ctr(beta_aes_key, beta_iv, serializedRoutingInfo)

    gamma = hmac(mac_key, beta)

  return ok((beta: beta, gamma: gamma))

proc computeDelta(s: seq[seq[byte]], msg: Message): Result[seq[byte], string] =
  let sLen = s.len
  var delta: seq[byte]

  for i in countdown(sLen - 1, 0):
    # delta_key = KDF("payload_enc_key", s_i) is the LIONESS seed for this layer.
    var delta_key = sha256DomSepKdf(PayloadEncKeyLabel, s[i])
    defer:
      burnMem(delta_key)

    var lion = Lioness.init(MixLionessScheme, delta_key).valueOr:
      return err("LIONESS init error: " & $error)
    defer:
      lion.clear()

    # The exit layer starts from the plaintext (which already carries the k
    # zero-byte integrity prefix from serialize); inner layers re-encrypt the
    # previous delta. Each layer is one in-place LIONESS encryption.
    if i == sLen - 1:
      delta = msg.serialize()
    lion.encrypt(delta).isOkOr:
      return err("LIONESS encrypt error: " & $error)

  return ok(delta)

type
  ReplyCredential* = object
    identifier: SURBIdentifier
    key: serialization.Key
    secret: serialization.Secret

  RawSurbReply* = object
    identifier*: SURBIdentifier
    encryptedPayload*: seq[byte]

func identifier*(credential: ReplyCredential): SURBIdentifier {.inline.} =
  credential.identifier

proc wipe*(credential: var ReplyCredential) =
  ## Clear retained reply secrets when their owner retires the credential.
  for secret in credential.secret.mitems:
    burnMem(secret)
  burnMem(credential.key)

proc `=destroy`(credential: var ReplyCredential) =
  credential.wipe()
  `=destroy`(credential.key)
  `=destroy`(credential.secret)

proc `=copy`(dst: var ReplyCredential, src: ReplyCredential) {.error.}
proc `=dup`(src: ReplyCredential): ReplyCredential {.error.}

proc createSURB*(
    publicKeys: openArray[FieldElement],
    delay: openArray[Delay],
    hops: openArray[Hop],
    id: SURBIdentifier,
    rng: Rng,
): Result[tuple[surb: SURB, credential: ReplyCredential], string] =
  if rng.isNil:
    return err("rng must not be nil")

  if id == default(SURBIdentifier):
    return err("id should be initialized")

  ?validatePathInputs(publicKeys, delay, hops)

  # Compute alpha and shared secrets
  var (alpha_0, s) = computeAlpha(publicKeys).valueOr:
    return err("Error in alpha generation: " & error)
  # The secrets move into the reply credential, or are wiped on failure.
  defer:
    for hopSecret in s.mitems:
      burnMem(hopSecret)

  # Compute beta and gamma
  let (beta_0, gamma_0) = computeBetaGamma(s, hops, delay, Hop(), id, rng).valueOr:
    return err("Error in beta and gamma generation: " & error)

  # Generate key
  var key = newSeqUninit[byte](k)
  rng.generate(key)

  return ok(
    (
      surb: SURB(hop: hops[0], header: Header.init(alpha_0, beta_0, gamma_0), key: key),
      credential: ReplyCredential(identifier: id, key: key, secret: move(s)),
    )
  )

proc useSURB*(surb: SURB, msg: Message): SphinxPacket =
  # The reply sender encrypts the payload once, using the reply key k~
  # (surb.key) directly as the LIONESS seed (LIP-183 §6.2.2). Inputs are
  # structurally valid (|k~| = k >= kappa, |payload| = PayloadSize >= 2*Mu), so
  # the LIONESS calls cannot fail here (serialize already asserts the size).
  var delta = msg.serialize()
  var lion = Lioness.init(MixLionessScheme, surb.key).expect("LIONESS init")
  defer:
    lion.clear()
  lion.encrypt(delta).expect("LIONESS encrypt")

  return SphinxPacket.init(surb.header, delta)

proc recoverSphinxReply*(
    credential: ReplyCredential, reply: RawSurbReply
): Result[seq[byte], string] =
  if credential.identifier != reply.identifier:
    return err("reply identifier does not match credential")

  # Independent, mutable buffer for in-place LIONESS.
  var delta = @(reply.encryptedPayload)

  # LIP-183 §7.3 step 1: re-apply the §6.2.1 layered LIONESS *encryption* over the
  # return-path secrets (i = L-1 downto 0), reversing each return hop's
  # decryption so that only the reply sender's initial encryption remains.
  for i in countdown(credential.secret.len - 1, 0):
    var delta_key = sha256DomSepKdf(PayloadEncKeyLabel, credential.secret[i])
    defer:
      burnMem(delta_key)

    var lion = Lioness.init(MixLionessScheme, delta_key).valueOr:
      return err("LIONESS init error: " & $error)
    defer:
      lion.clear()
    lion.encrypt(delta).isOkOr:
      return err("LIONESS encrypt error: " & $error)

  # LIP-183 §7.3 step 2: remove the reply sender's initial encryption, which used
  # the reply key k~ as the LIONESS seed (LIP-183 §6.2.2).
  var lion = Lioness.init(MixLionessScheme, credential.key).valueOr:
    return err("LIONESS init error: " & $error)
  defer:
    lion.clear()
  lion.decrypt(delta).isOkOr:
    return err("LIONESS decrypt error: " & $error)

  # LIP-183 §7.3 step 3: verify the k-byte zero integrity prefix (mirrors the
  # forward-path exit check) before recovering the message, so a tampered reply
  # is rejected instead of silently returning a corrupted message.
  if not delta.isZeros(0, k - 1):
    return err("reply payload integrity check failed")

  let deserializeMsg = Message.deserialize(delta).valueOr:
    return err("Message deserialization error: " & error)

  return ok(deserializeMsg)

proc wrapInSphinxPacket*(
    msg: Message,
    publicKeys: openArray[FieldElement],
    delay: openArray[Delay],
    hop: openArray[Hop],
    destHop: Hop,
): Result[SphinxPacket, string] =
  ?validatePathInputs(publicKeys, delay, hop)

  # Compute alpha and shared secrets
  var (alpha_0, s) = computeAlpha(publicKeys).valueOr:
    return err("Error in alpha generation: " & error)
  defer:
    for hopSecret in s.mitems:
      burnMem(hopSecret)

  # Compute beta and gamma
  let (beta_0, gamma_0) = computeBetaGamma(
    s, hop, delay, destHop, default(SURBIdentifier)
  ).valueOr:
    return err("Error in beta and gamma generation: " & error)

  # Compute delta
  let delta_0 = computeDelta(s, msg).valueOr:
    return err("Error in delta generation: " & error)

  # Serialize sphinx packet
  let sphinxPacket = SphinxPacket.init(Header.init(alpha_0, beta_0, gamma_0), delta_0)

  return ok(sphinxPacket)

type ProcessedSphinxPacket* = object
  case status*: ProcessingStatus
  of ProcessingStatus.Exit:
    destination*: Hop
    messageChunk*: seq[byte]
  of ProcessingStatus.Intermediate:
    nextHop*: Hop
    delay*: Delay
    serializedSphinxPacket*: seq[byte]
  of ProcessingStatus.Reply:
    id*: SURBIdentifier
    delta_prime*: seq[byte]
  else:
    discard

template extractSurbId(data: seq[byte]): SURBIdentifier =
  const startIndex = t * k
  const endIndex = startIndex + SurbIdLen - 1
  doAssert data.len > startIndex and endIndex < data.len
  var id: SURBIdentifier
  copyMem(addr id[0], addr data[startIndex], SurbIdLen)
  id

proc computeTag(sBytes: openArray[byte]): Tag {.raises: [].} =
  ## Compute replay detection tag as H(s) per spec Section 8.6.1 Step 2.
  sha256_hash(sBytes)

proc checkSharedSecret(s: FieldElement): Result[FieldElement, string] {.raises: [].} =
  # Low-order public inputs collapse X25519 output to zero; reject after multiplication
  # because that is the point where the subgroup check is observable for X25519.
  if s.isZeroFieldElement():
    return err("Invalid alpha: low-order shared secret")
  ok(s)

proc computeSharedSecret(
    alphaFE: FieldElement, privateKey: FieldElement
): Result[FieldElement, string] {.raises: [].} =
  checkSharedSecret(multiplyPointWithSecret(alphaFE, privateKey))

proc checkReplay*(
    sphinxPacket: SphinxPacket, privateKey: FieldElement, tm: var TagManager
): Result[tuple[isReplay: bool, sharedSecret: FieldElement], string] =
  ## Check if a Sphinx packet is a replay without doing full processing.
  ## Returns (isReplay, sharedSecret) to enable reuse of expensive EC multiplication.
  ## The tag is not added until MAC verification succeeds in processSphinxPacket.
  let
    (header, _) = sphinxPacket.get()
    (alpha, _, _) = header.get()

  # Compute shared secret
  let alphaFE = bytesToAlphaFieldElement(alpha).valueOr:
    return err("Invalid alpha: " & error)

  let s = computeSharedSecret(alphaFE, privateKey).valueOr:
    return err(error)

  # Compute tag as H(s) per spec
  let tag = computeTag(fieldElementToBytes(s))

  ok((isReplay: isTagSeen(tm, tag), sharedSecret: s))

proc isMacValid(beta, gamma, sBytes: seq[byte]): bool {.raises: [].} =
  var mac_key = deriveKey(MacKeyLabel, sBytes)
  defer:
    burnMem(mac_key)

  let expectedMac = hmac(mac_key, beta)
  # CT.isEqual compares only the shared prefix, so reject unequal lengths first.
  gamma.len == expectedMac.len and CT.isEqual(expectedMac, gamma)

proc peelLayer(
    alpha, beta, payload: seq[byte], alphaFE: FieldElement, sBytes: seq[byte]
): Result[ProcessedSphinxPacket, string] {.raises: [].} =
  ## Remove one layer of an authenticated packet, wiping everything derived from
  ## the shared secret (Mix Key Rotation spec §3.3).
  # Derive AES key and IV for the header (beta)
  var
    beta_aes_key = deriveKey(AesKeyLabel, sBytes)
    beta_iv = deriveKey(IvLabel, sBytes)

  # Decrypt one LIONESS layer of the payload. delta_key = KDF("payload_enc_key", s).
  var delta_key = sha256DomSepKdf(PayloadEncKeyLabel, sBytes)
  defer:
    burnMem(beta_aes_key)
    burnMem(beta_iv)
    burnMem(delta_key)
  # `var` forces a real mutable copy, so the shared input payload is not mutated.
  var delta_prime = payload
  var lion = Lioness.init(MixLionessScheme, delta_key).valueOr:
    return err("LIONESS init error: " & $error)
  defer:
    lion.clear()
  lion.decrypt(delta_prime).isOkOr:
    return err("LIONESS decrypt error: " & $error)

  # Compute B
  let zeroPadding = newSeq[byte]((t + 1) * k)
  let B = aes_ctr(beta_aes_key, beta_iv, beta & zeroPadding)

  # Every terminal header has a fixed k-byte zero marker. Any remaining
  # unused hop capacity is random padding; the receiver does not know L.
  if B.isZeros((t + 1) * k, ((t + 2) * k) - 1):
    let hop = Hop.deserialize(B[0 .. AddrSize - 1]).valueOr:
      return err(error)

    if B.isZeros(AddrSize, ((t + 1) * k) - 1):
      if delta_prime.isZeros(0, k - 1):
        let msg = Message.deserialize(delta_prime).valueOr:
          return err("Message deserialization error: " & error)
        return ok(
          ProcessedSphinxPacket(
            status: Exit, destination: hop, messageChunk: msg[0 .. MessageSize - 1]
          )
        )
      else:
        return err("payload integrity check failed")
    elif B.isZeros(0, (t * k) - 1):
      return ok(
        ProcessedSphinxPacket(
          status: Reply, id: B.extractSurbId(), delta_prime: delta_prime
        )
      )
  else:
    # Extract routing information from B
    let routingInfo = RoutingInfo.deserialize(B).valueOr:
      return err("Routing info deserialization error: " & error)

    let (address, delay, gamma_prime, beta_prime) = routingInfo.getRoutingInfo()

    # Compute alpha
    var blinderInput = alpha & sBytes
    defer:
      burnMem(blinderInput)
    var blinder = bytesToFieldElement(sha256_hash(blinderInput)).valueOr:
      return err("Error in bytes to field element conversion: " & error)
    defer:
      burnMem(blinder)

    let alpha_prime = multiplyPointWithSecret(alphaFE, blinder)

    # Serialize sphinx packet
    let sphinxPkt = SphinxPacket.init(
      Header.init(fieldElementToBytes(alpha_prime), beta_prime, gamma_prime),
      delta_prime,
    )

    return ok(
      ProcessedSphinxPacket(
        status: Intermediate,
        nextHop: address,
        delay: delay,
        serializedSphinxPacket: sphinxPkt.serialize(),
      )
    )

proc peelLayerIfNew(
    tagStatus: TagInsertStatus,
    alpha, beta, payload: seq[byte],
    alphaFE: FieldElement,
    sBytes: seq[byte],
): Result[ProcessedSphinxPacket, string] {.raises: [].} =
  ## Peel the layer only when the packet's tag was newly stored.
  case tagStatus
  of TagAlreadyPresent:
    ok(ProcessedSphinxPacket(status: Duplicate))
  of TagCacheFull:
    ok(ProcessedSphinxPacket(status: ReplayCacheFull))
  of TagAdded:
    peelLayer(alpha, beta, payload, alphaFE, sBytes)

proc processSphinxPacket*(
    sphinxPacket: SphinxPacket,
    privateKey: FieldElement,
    tm: var TagManager,
    sharedSecret: Opt[FieldElement] = Opt.none(FieldElement),
): Result[ProcessedSphinxPacket, string] {.raises: [].} =
  let
    (header, payload) = sphinxPacket.get()
    (alpha, beta, gamma) = header.get()

  # Validate alpha encoding even when sharedSecret is supplied; alpha still
  # drives MAC and blinding.
  let alphaFE = bytesToAlphaFieldElement(alpha).valueOr:
    return err("Invalid alpha: " & error)

  let s = sharedSecret.valueOr:
    computeSharedSecret(alphaFE, privateKey).valueOr:
      return err(error)

  if s.isZeroFieldElement():
    return err("Invalid alpha: low-order shared secret")

  let sBytes = fieldElementToBytes(s)

  # Compute tag as H(s) per spec Section 8.6.1 Step 2
  let tag = computeTag(sBytes)

  # A supplied sharedSecret comes from checkReplay, which has checked the tag.
  if sharedSecret.isNone and isTagSeen(tm, tag):
    return ok(ProcessedSphinxPacket(status: Duplicate))

  if not isMacValid(beta, gamma, sBytes):
    return ok(ProcessedSphinxPacket(status: InvalidMAC))

  # Atomically add the replay tag only after authentication succeeds.
  peelLayerIfNew(tm.tryAddTag(tag), alpha, beta, payload, alphaFE, sBytes)

type
  KeyMatchStatus* = enum
    NoKeyMatched
    KeyMatched
    KeyReplayed
    KeyTableFull

  KeyMatch* = object
    case status*: KeyMatchStatus
    of KeyMatched:
      key*: MixKey
      sharedSecret: FieldElement
    else:
      discard

proc matchKey*(
    sphinxPacket: SphinxPacket, candidates: openArray[MixKey]
): Result[KeyMatch, string] {.raises: [].} =
  ## Find the candidate key the packet was built for, without storing its tag,
  ## trying the candidates in order and stopping at the first that has seen the
  ## packet or that it was built for (Mix Key Rotation spec §6). Destroyed keys
  ## never match. KeyTableFull means the packet was built for a key whose replay
  ## table is full (Mix Key Rotation spec §3.4). A KeyMatched packet is
  ## completed by `processSphinxPacket(packet, match)`.
  let
    (header, _) = sphinxPacket.get()
    (alpha, beta, gamma) = header.get()

  let alphaFE = bytesToAlphaFieldElement(alpha).valueOr:
    return err("Invalid alpha: " & error)

  for key in candidates:
    if key.isDestroyed:
      continue
    var secret = checkSharedSecret(?key.multiply(alphaFE)).valueOr:
      return err(error)
    var sBytes = fieldElementToBytes(secret)
    defer:
      burnMem(secret)
      burnMem(sBytes)

    if key.isTagSeen(computeTag(sBytes)):
      return ok(KeyMatch(status: KeyReplayed))
    if isMacValid(beta, gamma, sBytes):
      if key.isReplayTableFull:
        return ok(KeyMatch(status: KeyTableFull))
      return ok(KeyMatch(status: KeyMatched, key: key, sharedSecret: secret))
  ok(KeyMatch(status: NoKeyMatched))

proc wipe*(match: var KeyMatch) {.raises: [].} =
  ## Wipe the shared secret of a match that is not processed, and reset it to
  ## NoKeyMatched (Mix Key Rotation spec §3.3).
  if match.status == KeyMatched:
    burnMem(match.sharedSecret)
  match = KeyMatch(status: NoKeyMatched)

proc processSphinxPacket*(
    sphinxPacket: SphinxPacket, match: var KeyMatch
): Result[ProcessedSphinxPacket, string] {.raises: [].} =
  ## Complete a packet `matchKey` matched, storing its tag in the matched key's
  ## replay table. The match is consumed: its shared secret is wiped and its
  ## status reset to NoKeyMatched. The key's acceptance window is not rechecked.
  if match.status != KeyMatched:
    return err("Unmatched packet: " & $match.status)
  defer:
    burnMem(match.sharedSecret)
    match = KeyMatch(status: NoKeyMatched)

  let
    (header, payload) = sphinxPacket.get()
    (alpha, beta, gamma) = header.get()
    key = match.key

  let alphaFE = bytesToAlphaFieldElement(alpha).valueOr:
    return err("Invalid alpha: " & error)

  # The key can be destroyed between matchKey and this call.
  if key.isDestroyed:
    return err("Destroyed mix key")

  var sBytes = fieldElementToBytes(match.sharedSecret)
  defer:
    burnMem(sBytes)

  # Rechecked so that a match applied to another packet stores no tag.
  if not isMacValid(beta, gamma, sBytes):
    return ok(ProcessedSphinxPacket(status: InvalidMAC))

  peelLayerIfNew(key.addTag(computeTag(sBytes)), alpha, beta, payload, alphaFE, sBytes)
