# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

import
  ./libp2p_mix/[
    mix_protocol, mix_node, entry_connection, exit_layer, spam_protection,
    delay_strategy, pool,
  ]
import libp2p/stream/connection
import chronos
from ./libp2p_mix/serialization import SURB
from ./libp2p_mix/sphinx import ReplyCredential, RawSurbReply, identifier

export toConnection
export MixProtocolID
export MixProtocol
export MixDelivery
export MixDeliveryHandler
export RawSurbReplyHandler

export get
export `new`
export init
export getMaxMessageSizeForCodec
export send
export createSurb
export sendWithSurb
export registerMixDeliveryHandler
export unregisterMixDeliveryHandler
export registerRawSurbReplyHandler
export unregisterRawSurbReplyHandler
export MixDestination
export MixParameters
export destReadBehaviorCb
export DestReadBehavior
export registerDestReadBehavior
export localMixPubInfo
export setLocalMultiAddr
export SURB
export ReplyCredential
export RawSurbReply
export identifier
export recoverReply
export ReplyRecoveryErrorKind
export ReplyRecoveryError

# Spam protection exports
export SpamProtection
export generateProof
export verifyProof

export NoSamplingDelayStrategy
export ExponentialDelayStrategy
export SpamProtectionDelayStrategy

export mix_node

export MixNodePool
export add
export remove
export peerIds

proc readLp*(maxSize: int): DestReadBehavior =
  ## Create a read behavior that reads length-prefixed messages (varint-encoded length).
  ## The exit layer will automatically restore the length prefix for the reply.
  let callback = proc(
      conn: Connection
  ): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]).} =
    await conn.readLp(maxSize)

  DestReadBehavior(callback: callback, usesLengthPrefix: true)

proc readExactly*(nBytes: int): DestReadBehavior =
  ## Create a read behavior that reads exactly nBytes without any length prefix.
  ## The exit layer will not add a length prefix to the reply.
  let callback = proc(
      conn: Connection
  ): Future[seq[byte]] {.async: (raises: [CancelledError, LPStreamError]).} =
    let buf = newSeqUninit[byte](nBytes)
    await conn.readExactly(addr buf[0], nBytes)
    return buf

  DestReadBehavior(callback: callback, usesLengthPrefix: false)

when defined(libp2p_mix_experimental_exit_is_dest):
  export exitNode
  export forwardToAddr
