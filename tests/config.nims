import ../config.nims

--threads:
  on
--d:
  metrics
--d:
  libp2p_agents_metrics
# -d:libp2p_protobuf_metrics is unusable on libp2p 2.2.0: modules that
# instantiate serializerFor/decodeFor with metrics enabled (e.g.
# protocols/identify.nim) do not import utils/protobuf_metrics under the
# define, so the injected counter identifiers fail to resolve.
--d:
  libp2p_network_protocols_metrics
--d:
  libp2p_mplex_metrics
--d:
  unittestPrintTime
