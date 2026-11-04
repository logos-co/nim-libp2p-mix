# SPDX-License-Identifier: Apache-2.0 OR MIT

{.used.}

import libp2p_mix
import libp2p/crypto/crypto

proc buildKeyRing(rng: Rng): MixKeyRing {.used.} =
  ## Compiles only if the facade, without chronos, is enough to build a key ring.
  MixKeyRing.new(
    KeySchedule.init().get(),
    rng,
    replayTableCapacity = 16,
    publishedThrough = Opt.none(KeyPeriod),
  )

static:
  doAssert declared(buildCoverPacket)
  doAssert declared(sendCoverPacket)
  doAssert declared(sendSurbReply)
  doAssert declared(MixKeyRing)
  doAssert declared(keyPeriod)
  doAssert declared(acceptanceWindow)
  doAssert declared(MixKeyEntries)
  doAssert declared(setEntriesHandler)
  doAssert declared(publishedEntries)
