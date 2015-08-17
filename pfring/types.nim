import posix
import times

type
  pfring* {.final, pure.} = ref object
  sk_buff* {.final, pure.} = ref object
  pfring_extended_pkthdr_tx* {.final, pure.} = ref object
    bounce_interface*: cint
    reserved*: sk_buff

  pkt_parsing_info* {.final, pure.} = ref object
    dmac*: uint8
    smac*: uint8

  pfring_extended_pkthdr* {.final, pure.} = ref object
    timestamp_ns*: uint64
    flags*: uint32
    rx_direction*: uint8
    if_index*: int32
    pkt_hash*: uint32
    tx*: pfring_extended_pkthdr_tx
    parsed_header_len*: uint16
    parsed_pkt*: pkt_parsing_info

  pfring_pkthdr* {.final, pure.} = ref object
    ts*: Timeval
    caplen*: cint
    length*: cint
    extended_pkthdr*: pfring_extended_pkthdr


  pfring_stat* {.final, pure.} = ref object
  pfringProcessPacket* {.final, pure.} = ref object
  hw_filtering_rule* {.final, pure.} = ref object
  packet_direction* {.final, pure.} = ref object
  socket_mode* {.final, pure.} = ref object
  cluster_type* {.final, pure.} = ref object
  hash_filtering_rule* {.final, pure.} = ref object
  filtering_rule* {.final, pure.} = ref object
  virtual_filtering_device_info* {.final, pure.} = ref object
  filtering_mode* {.final, pure.} = ref object
  pfring_pkt_buff* {.final, pure.} = ref object
  pfring_bundle* {.final, pure.} = ref object
  bundle_read_policy* {.final, pure.} = ref object
  pfring_card_settings* {.final, pure.} = ref object
  bpf_program* {.final, pure.} = ref object
  pfring_bpf_program* {.final, pure.} = ref object

const
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
