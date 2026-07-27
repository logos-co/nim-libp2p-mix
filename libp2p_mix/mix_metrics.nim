# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) Status Research & Development GmbH

{.push raises: [].}

import metrics

declarePublicCounter mix_messages_recvd, "number of mix messages received", ["type"]

declarePublicCounter mix_messages_forwarded,
  "number of mix messages forwarded", ["type"]

declarePublicCounter mix_messages_error,
  "number of mix messages failed processing", ["type", "error"]

declarePublicGauge mix_pool_size, "number of nodes in the pool"

declarePublicCounter mix_cover_emitted, "number of cover packets emitted", ["type"]

declarePublicCounter mix_cover_received,
  "number of cover packets received at exit (loop return)"

declarePublicCounter mix_slot_claim_rejected,
  "number of slot claim rejections", ["type"]

declarePublicCounter mix_cover_error, "number of cover traffic errors", ["error"]

declarePublicCounter mix_cover_precomputed,
  "number of cover packets pre-computed per epoch"

declarePublicGauge mix_surb_creds_active,
  "number of SURB reply credentials currently held by the sender"

declarePublicCounter mix_surb_creds_expired,
  "number of SURB reply credentials reclaimed after TTL (replies never arrived)"

declarePublicCounter mix_surb_creds_rejected,
  "number of sends refused because the SURB credential store was at capacity"

declarePublicCounter mix_reply_timeouts,
  "number of sends whose reply did not arrive within the connection timeout"
