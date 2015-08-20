import posix
import times

{.pragma: st,
  pure,
  final,
  header: "<linux/pf_ring.h>",
  importc: "struct $1"
.}

{.pragma: pf,
  pure,
  final,
.}


type
  pfring* {.st.} = ref object
  sk_buff {.st.} = ref object
  pfring_extended_pkthdr_tx {.final, pure.} = object
    bounce_interface*: cint
    reserved*: sk_buff

  ip_addr {.pf.} = object
    v6*: In6Addr
    v4*: uint32

  pkt_parsing_info_tcp {.final, pure.} = object
    flags*: uint8
    seq_num*: uint32
    ack_num*: uint32

  tunnel_info {.pf.} = object
    tunnel_id*: uint32
    tunneled_proto*: uint8
    tunneled_ip_src*: ip_addr
    tunneled_ip_dst*: ip_addr
    tunneled_l4_src_port*: uint16
    tunneled_l4_dst_port*: uint16

  pkt_offset {.pf.} = object
    eth_offset*: int16
    vlan_offset*: int16
    l3_offset*: int16
    l4_offset*: int16
    payload_offset*: int16

  pkt_parsing_info {.pf.} = object
    dmac*: uint8
    smac*: uint8
    eth_type*: uint16
    vlan_id*: uint16
    ip_version*: uint8
    l3_proto*: uint8
    ip_tos*: uint8
    ip_src*: ip_addr
    ip_dst*: ip_addr
    l4_src_port*: uint16
    l4_dst_port*: uint16
    tcp*: pkt_parsing_info_tcp
    tunnel*: tunnel_info
    last_matched_plugin_id*: uint16
    last_matched_rule_id*: uint16
    offset*: pkt_offset

  pfring_extended_pkthdr {.pf.} = object
    timestamp_ns*: uint64
    flags*: uint32
    rx_direction*: uint8
    if_index*: int32
    pkt_hash*: uint32
    tx*: pfring_extended_pkthdr_tx
    parsed_header_len*: uint16
    parsed_pkt*: pkt_parsing_info

  pfring_pkthdr* {.pf.} = object
    ts*: Timeval
    caplen*: cuint
    length*: cuint
    extended_pkthdr*: pfring_extended_pkthdr


  pfring_stat* {.pf.} = ref object
    recv*: uint64
    drop*: uint64

  hw_filtering_rule* {.pf.} = ref object

  packet_direction* = enum
    rx_and_tx_direction,
    rx_only_direction,
    tx_only_direction

  socket_mode* = enum
    send_and_recv_mode,
    send_only_mode,
    recv_only_mode

  cluster_type* = enum
    cluster_per_flow,
    cluster_round_robin,
    cluster_per_flow_2_tuple,
    cluster_per_flow_4_tuple,
    cluster_per_flow_5_tuple,
    cluster_per_flow_tcp_5_tuple

  hash_filtering_rule* {.pf.} = ref object
  filtering_rule* {.pf.} = ref object
  virtual_filtering_device_info* {.pf.} = ref object
  filtering_mode* {.pf.} = ref object
  pfring_pkt_buff* {.pf.} = ref object
  pfring_bundle* {.pf.} = ref object
  bundle_read_policy* {.pf.} = ref object
  pfring_card_settings* {.pf.} = ref object
  bpf_program* {.pf.} = ref object
  pfring_bpf_program* {.pf.} = ref object

const
  IPv4*: uint16 = 0x0800
  IPv6*: uint16 = 0x86DD

  # TCP flag
  TH_FIN* = 0x01
  TH_SYN* = 0x02
  TH_RST* = 0x04
  TH_PUSH* = 0x08
  TH_ACK* = 0x10
  TH_URG* = 0x20
  TH_ECNECHO* = 0x40
  TH_CWR* =  0x80

  PF_RING_ZC_SYMMETRIC_RSS* = 1 shl 0
  PF_RING_REENTRANT* = 1 shl 1
  PF_RING_LONG_HEADER* = 1 shl 2
  PF_RING_PROMISC* = 1 shl 3
  PF_RING_TIMESTAMP* = 1 shl 4
  PF_RING_HW_TIMESTAMP* = 1 shl 5
  PF_RING_RX_PACKET_BOUNCE* = 1 shl 6
  PF_RING_ZC_FIXED_RSS_Q_0* = 1 shl 7
  PF_RING_STRIP_HW_TIMESTAMP* = 1 shl 8
  PF_RING_DO_NOT_PARSE* = 1 shl 9
  PF_RING_DO_NOT_TIMESTAMP* = 1 shl 10
  PF_RING_CHUNK_MODE* = 1 shl 11
  PF_RING_IXIA_TIMESTAMP* = 1 shl 12
  PF_RING_USERSPACE_BPF* = 1 shl 13
  PF_RING_ZC_NOT_REPROGRAM_RSS* = 1 shl 14
  PF_RING_VSS_APCON_TIMESTAMP* = 1 shl 15
  PF_RING_ZC_IPONLY_RSS* = 1 shl 16
  PF_RING_DNA_SYMMETRIC_RSS* = PF_RING_ZC_SYMMETRIC_RSS
  PF_RING_DNA_FIXED_RSS_Q_0* = PF_RING_ZC_FIXED_RSS_Q_0
