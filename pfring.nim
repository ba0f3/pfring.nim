{.passL: "-lpfring -lpcap -lnuma -lrt".}

{.pragma: pf,
  cdecl,
  importc
.}

type
  pfring* {.final, pure.} = ref object
  pfring_pkthdr* {.final, pure.} = ref object
  pfring_stat* {.final, pure.} = ref object
  pfringProcessPacket {.final, pure.} = ref object
  hw_filtering_rule {.final, pure.} = ref object

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

proc pfring_open*(device: cstring, caplen, flags: cuint): pfring {.pf.}
proc pfring_open_consumer*(device: cstring, caplen, flags: cuint, cpi: uint8, cd: cstring, cdl: cint): pfring {.pf.}
proc pfring_open_multichannel*(device: cstring, caplen, flags: cuint, rings: array[1..32, pfring]): uint8 {.pf.}
proc pfring_shutdown*(ring: pfring) {.pf.}
proc pfring_config*(cpuPercentage: cshort) {.pf.}
proc pfring_loop*(ring: pfring, looper: pfringProcessPacket, userBytes: pointer, wfp: uint8): cint {.pf.}
proc pfring_breakloop*(ring: pfring) {.pf.}
proc pfring_close*(ring: pfring) {.pf.}
proc pfring_stats*(ring: pfring, stats: pfring_stat): cint {.pf.}
proc pfring_recv*(ring: pfring, buf: pointer, bufLen: cint, hdr: pfring_pkthdr, wfip: uint8): cint {.pf.}
proc pfring_recv_parsed*(ring: pfring, buf: pointer, bufLen: cint, hdr: pfring_pkthdr, wfip, level, addTimestamp, addHash: uint8): cint {.pf.}
proc pfring_set_poll_watermark*(ring: pfring, watermark: uint16): cint {.pf.}
proc pfring_set_poll_duration*(ring: pfring, duration: cuint): cint {.pf.}
proc pfring_set_tx_watermark*(ring: pfring, watermark: uint16): cint {.pf.}
proc pfring_add_hw_rule*(rung: pfring, rule: hw_filtering_rule): cint {.pf.}
proc pfring_remove_hw_rule*(ring: pfring, rule_id: uint16): cint {.pf.}
proc pfring_set_channel_id*(ring: pfring, channel_id: uint32): cint {.pf.}
proc pfring_set_channel_mask*(ring: pfring, channel_mask: uint64): cint {.pf.}
proc pfring_set_application_name(ring: pfring, name: cstring): int {.pf.}
proc pfring_set_application_stats*(ring: pfring, stats: cstring): int {.pf.}
proc pfring_get_appl_stats_file_name*(ring: pfring, path: cstring, path_len: cuint): cstring {.pf.}
proc pfring_bind*(ring: pfring, device: cstring): int {.pf.}
proc pfring_send*(ring: pfring, pkt: cstring, pkt_len, cuint, flush_packet: uint8): int {.pf.}


when isMainModule:
  var pd = pfring_open("eth0", 8196, PF_RING_ZC_SYMMETRIC_RSS)
  if pd.isNil:
    quit "pfring_open error " & getCurrentExceptionMsg()
  var r = pfring_set_application_name(pd, "pfring.nim")
  echo r
  var buf: cstring = ""
  var hdr: pfring_pkthdr
  new(hdr)
  var res = pfring_recv(pd, addr buf, 0, hdr, 0)
  echo res
  echo buf
  pfring_shutdown(pd)
