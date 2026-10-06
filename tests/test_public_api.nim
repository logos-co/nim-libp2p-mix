# SPDX-License-Identifier: Apache-2.0 OR MIT

{.used.}

import libp2p_mix

static:
  doAssert declared(buildCoverPacket)
  doAssert declared(sendCoverPacket)
  doAssert declared(sendSurbReply)
