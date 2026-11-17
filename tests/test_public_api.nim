# SPDX-License-Identifier: Apache-2.0 OR MIT

{.used.}

import libp2p_mix
import libp2p/crypto/[crypto, curve25519]

proc buildKeyRing(rng: Rng): MixKeyRing {.used.} =
  ## Compiles only if the facade, without chronos, is enough to build a key ring
  ## and receive its keys.
  let ring =
    MixKeyRing.new(KeyRotationConfig.init().get(), rng, replayTableCapacity = 16)
  ring.setKeyHandler(
    proc(publicKey: Curve25519Key) {.gcsafe, raises: [].} =
      discard
  )
  ring

static:
  doAssert declared(buildCoverPacket)
  doAssert declared(sendCoverPacket)
  doAssert declared(sendSurbReply)
  doAssert declared(MixKeyRing)
  doAssert declared(acceptanceWindow)
  doAssert declared(setKeyHandler)
