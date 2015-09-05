#
#
#  (C) 2005-14 - ntop.org
#
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU Lesses General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#

{.passL: "-lpfring -lpcap -lnuma -lrt".}
{.deadCodeElim: on.}

import posix
const
  MAX_CAPLEN* = 65535
  TH_FIN* = 0x01
  TH_SYN* = 0x02
  TH_RST* = 0x04
  TH_PUSH* = 0x08
  TH_ACK* = 0x10
  TH_URG* = 0x20
  TH_ECNECHO* = 0x40
  TH_CWR* =  0x80


{.pragma: pfring,
 cdecl,
 header: "<pfring.h>",
 importc.}


# *********************************
type
  sk_buff = ref object
  pfring_extended_pkthdr_tx {.final, pure.} = object
    bounce_interface*: cint
    reserved*: sk_buff

  ip_addr = object {.union.}
    v6*: In6Addr           # IPv6 src/dst IP addresses (Network byte order)
    v4*: int32            # IPv4 src/dst IP addresses

  pkt_parsing_info_tcp = object
    flags*: uint8
    seq_num*: uint32
    ack_num*: uint32

  tunnel_info = object
    tunnel_id*: uint32
    tunneled_proto*: uint8
    tunneled_ip_src*: ip_addr
    tunneled_ip_dst*: ip_addr
    tunneled_l4_src_port*: uint16
    tunneled_l4_dst_port*: uint16

  pkt_offset = object
    eth_offset*: int16
    vlan_offset*: int16
    l3_offset*: int16
    l4_offset*: int16
    payload_offset*: int16

  pkt_parsing_info = object
    dmac*: array[0..5, char]
    smac*: array[0..5, char]
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

  pfring_extended_pkthdr {.pure, final.} = object
    timestamp_ns*: uint64
    flags*: uint32
    rx_direction*: uint8
    if_index*: int32
    pkt_hash*: uint32
    tx*: pfring_extended_pkthdr_tx
    parsed_header_len*: uint16
    parsed_pkt*: pkt_parsing_info

  pfring_pkthdr* = object
    ts*: Timeval
    caplen*: cuint
    length*: cuint
    extended_hdr*: pfring_extended_pkthdr

  pfring_stat* = object
    recv*: uint64
    drop*: uint64

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

  pfring_bpf_program* = object
    bf_len*: u_int
    bf_insns*: pointer

  hash_filtering_rule* = object
  filtering_rule* = object
  virtual_filtering_device_info* = object

  filtering_mode* {.size: sizeof(cint).} = enum
    hardware_and_software = 0, hardware_only, software_only

  pfring_pkt_buff = object
  hw_filtering_rule = object
  pfring_device_type = object
  FlowSlotInfo = object
  pthread_rwlock_t = object
  sockaddr_ll = object
  pollfd = object

  pfring_card_settings = object
    max_packet_size*: uint32
    rx_ring_slots*: uint32
    tx_ring_slots*: uint32


  INNER_C_STRUCT_8320161996705125961 = object
    force_timestamp*: uint8
    is_silicom_hw_timestamp_card*: uint8
    enable_hw_timestamp*: uint8
    last_hw_timestamp*: Timespec

  INNER_C_STRUCT_2972418661010263783 = object
    enabled_rx_packet_send*: uint8
    last_received_hdr*: ptr pfring_pkthdr #
                                          #       Header of the past packet
                                          #       that has been received on this socket
                                          #
  zc_dev_info = object
  zc_dev_operation = object
  INNER_C_STRUCT_15956139561790962620 = object
    num_rx_pkts_before_dna_sync*: uint16
    num_tx_pkts_before_dna_sync*: uint16
    dna_rx_sync_watermark*: uint16
    dna_tx_sync_watermark*: uint16
    tot_dna_read_pkts*: uint64
    tot_dna_lost_pkts*: uint64
    rx_reg*: uint32
    tx_reg*: uint32
    last_rx_slot_read*: uint32
    num_rx_slots_per_chunk*: uint32
    num_tx_slots_per_chunk*: uint32
    dna_dev*: zc_dev_info
    rx_reg_ptr*: ptr uint32
    tx_reg_ptr*: ptr uint32
    mpc_reg_ptr*: ptr uint32
    qprdc_reg_ptr*: ptr uint32
    rnbc_reg_ptr*: ptr uint32
    rqdpc_reg_ptr*: ptr uint32
    gorc_reg_ptr*: ptr uint32
    last_dna_operation*: zc_dev_operation

  INNER_C_STRUCT_6977292814936016408 = object
    device_id*: int8
    port_id*: int8

  pfring* = object
    initialized*: uint8
    enabled*: uint8
    long_header*: uint8
    force_timestamp*: uint8
    strip_hw_timestamp*: uint8
    disable_parsing*: uint8
    disable_timestamp*: uint8
    ixia_timestamp_enabled*: uint8
    vss_apcon_timestamp_enabled*: uint8
    chunk_mode_enabled*: uint8
    userspace_bpf*: uint8
    force_userspace_bpf*: uint8
    rss_mode*: uint32
    direction*: packet_direction # Specify the capture direction for packets
    mode*: socket_mode
    userspace_bpf_filter*: pfring_bpf_program # Hardware Timestamp
    hw_ts*: INNER_C_STRUCT_8320161996705125961
    tx*: INNER_C_STRUCT_2972418661010263783
    zc_device*: uint8 # FIXX these fields should be moved in ->priv_data
                         # DNA (Direct NIC Access) only
    dna*: INNER_C_STRUCT_15956139561790962620
    priv_data*: pointer       # module private data
    close*: proc (a2: ptr pfring) {.cdecl.}
    stats*: proc (a2: ptr pfring; a3: ptr pfring_stat): cint {.cdecl.}
    recv*: proc (a2: ptr pfring; a3: ptr cstring; a4: u_int;
                 a5: ptr pfring_pkthdr; a6: uint8): cint {.cdecl.}
    set_poll_watermark*: proc (a2: ptr pfring; a3: uint16): cint {.cdecl.}
    set_poll_duration*: proc (a2: ptr pfring; a3: u_int): cint {.cdecl.}
    set_tx_watermark*: proc (a2: ptr pfring; a3: uint16): cint {.cdecl.}
    set_channel_id*: proc (a2: ptr pfring; a3: uint32): cint {.cdecl.}
    set_channel_mask*: proc (a2: ptr pfring; a3: uint64): cint {.cdecl.}
    set_application_name*: proc (a2: ptr pfring; a3: cstring): cint {.cdecl.}
    set_application_stats*: proc (a2: ptr pfring; a3: cstring): cint {.cdecl.}
    get_appl_stats_file_name*: proc (ring: ptr pfring; path: cstring;
                                     path_len: u_int): cstring {.cdecl.}
    `bind`*: proc (a2: ptr pfring; a3: cstring): cint {.cdecl.}
    send*: proc (a2: ptr pfring; a3: cstring; a4: u_int; a5: uint8): cint {.
        cdecl.}
    send_ifindex*: proc (a2: ptr pfring; a3: cstring; a4: u_int; a5: uint8;
                         a6: cint): cint {.cdecl.}
    send_get_time*: proc (a2: ptr pfring; a3: cstring; a4: u_int;
                          a5: ptr Timespec): cint {.cdecl.}
    get_num_rx_channels*: proc (a2: ptr pfring): uint8 {.cdecl.}
    get_card_settings*: proc (a2: ptr pfring; a3: ptr pfring_card_settings): cint {.
        cdecl.}
    set_sampling_rate*: proc (a2: ptr pfring; a3: uint32): cint {.cdecl.}
    get_selectable_fd*: proc (a2: ptr pfring): cint {.cdecl.}
    set_direction*: proc (a2: ptr pfring; a3: packet_direction): cint {.cdecl.}
    set_socket_mode*: proc (a2: ptr pfring; a3: socket_mode): cint {.cdecl.}
    set_cluster*: proc (a2: ptr pfring; a3: u_int; a4: cluster_type): cint {.
        cdecl.}
    remove_from_cluster*: proc (a2: ptr pfring): cint {.cdecl.}
    set_master_id*: proc (a2: ptr pfring; a3: uint32): cint {.cdecl.}
    set_master*: proc (a2: ptr pfring; a3: ptr pfring): cint {.cdecl.}
    get_ring_id*: proc (a2: ptr pfring): uint16 {.cdecl.}
    get_num_queued_pkts*: proc (a2: ptr pfring): uint32 {.cdecl.}
    get_packet_consumer_mode*: proc (a2: ptr pfring): uint8 {.cdecl.}
    set_packet_consumer_mode*: proc (a2: ptr pfring; a3: uint8; a4: cstring;
                                     a5: u_int): cint {.cdecl.}
    get_hash_filtering_rule_stats*: proc (a2: ptr pfring;
        a3: ptr hash_filtering_rule; a4: cstring; a5: ptr u_int): cint {.cdecl.}
    handle_hash_filtering_rule*: proc (a2: ptr pfring;
                                       a3: ptr hash_filtering_rule; a4: cstring): cint {.
        cdecl.}
    purge_idle_hash_rules*: proc (a2: ptr pfring; a3: uint16): cint {.cdecl.}
    add_filtering_rule*: proc (a2: ptr pfring; a3: ptr filtering_rule): cint {.
        cdecl.}
    remove_filtering_rule*: proc (a2: ptr pfring; a3: uint16): cint {.cdecl.}
    purge_idle_rules*: proc (a2: ptr pfring; a3: uint16): cint {.cdecl.}
    get_filtering_rule_stats*: proc (a2: ptr pfring; a3: uint16; a4: cstring;
                                     a5: ptr u_int): cint {.cdecl.}
    toggle_filtering_policy*: proc (a2: ptr pfring; a3: uint8): cint {.cdecl.}
    enable_rss_rehash*: proc (a2: ptr pfring): cint {.cdecl.}
    poll*: proc (a2: ptr pfring; a3: u_int): cint {.cdecl.}
    is_pkt_available*: proc (a2: ptr pfring): cint {.cdecl.}
    next_pkt_time*: proc (a2: ptr pfring; a3: ptr Timespec): cint {.cdecl.}
    next_pkt_raw_timestamp*: proc (a2: ptr pfring; ts: ptr uint64): cint {.
        cdecl.}
    version*: proc (a2: ptr pfring; a3: ptr uint32): cint {.cdecl.}
    get_bound_device_address*: proc (a2: ptr pfring; a3: array[6, char]): cint {.
        cdecl.}
    get_bound_device_ifindex*: proc (a2: ptr pfring; a3: ptr cint): cint {.cdecl.}
    get_device_ifindex*: proc (a2: ptr pfring; a3: cstring; a4: ptr cint): cint {.
        cdecl.}
    get_slot_header_len*: proc (a2: ptr pfring): uint16 {.cdecl.}
    set_virtual_device*: proc (a2: ptr pfring;
                               a3: ptr virtual_filtering_device_info): cint {.
        cdecl.}
    add_hw_rule*: proc (a2: ptr pfring; a3: ptr hw_filtering_rule): cint {.cdecl.}
    remove_hw_rule*: proc (a2: ptr pfring; a3: uint16): cint {.cdecl.}
    loopback_test*: proc (a2: ptr pfring; a3: cstring; a4: u_int; a5: u_int): cint {.
        cdecl.}
    enable_ring*: proc (a2: ptr pfring): cint {.cdecl.}
    disable_ring*: proc (a2: ptr pfring): cint {.cdecl.}
    shutdown*: proc (a2: ptr pfring) {.cdecl.}
    set_bpf_filter*: proc (a2: ptr pfring; a3: cstring): cint {.cdecl.}
    remove_bpf_filter*: proc (a2: ptr pfring): cint {.cdecl.}
    get_device_clock*: proc (a2: ptr pfring; a3: ptr Timespec): cint {.cdecl.}
    set_device_clock*: proc (a2: ptr pfring; a3: ptr Timespec): cint {.cdecl.}
    adjust_device_clock*: proc (a2: ptr pfring; a3: ptr Timespec; a4: int8): cint {.
        cdecl.}
    sync_indexes_with_kernel*: proc (a2: ptr pfring) {.cdecl.}
    send_last_rx_packet*: proc (a2: ptr pfring; a3: cint): cint {.cdecl.}
    get_pkt_buff_data*: proc (a2: ptr pfring; a3: ptr pfring_pkt_buff): ptr cstring {.
        cdecl.}
    set_pkt_buff_len*: proc (a2: ptr pfring; a3: ptr pfring_pkt_buff;
                             a4: uint32): cint {.cdecl.}
    set_pkt_buff_ifindex*: proc (a2: ptr pfring; a3: ptr pfring_pkt_buff;
                                 a4: cint): cint {.cdecl.}
    add_pkt_buff_ifindex*: proc (a2: ptr pfring; a3: ptr pfring_pkt_buff;
                                 a4: cint): cint {.cdecl.}
    alloc_pkt_buff*: proc (a2: ptr pfring): ptr pfring_pkt_buff {.cdecl.}
    release_pkt_buff*: proc (a2: ptr pfring; a3: ptr pfring_pkt_buff) {.cdecl.}
    recv_pkt_buff*: proc (a2: ptr pfring; a3: ptr pfring_pkt_buff;
                          a4: ptr pfring_pkthdr; a5: uint8): cint {.cdecl.}
    send_pkt_buff*: proc (a2: ptr pfring; a3: ptr pfring_pkt_buff; a4: uint8): cint {.
        cdecl.}
    flush_tx_packets*: proc (a2: ptr pfring) {.cdecl.}
    register_zerocopy_tx_ring*: proc (a2: ptr pfring; a3: ptr pfring): cint {.
        cdecl.}
    recv_chunk*: proc (a2: ptr pfring; chunk: ptr pointer;
                       chunk_len: ptr uint32;
                       wait_for_incoming_chunk: uint8): cint {.cdecl.}
    set_bound_dev_name*: proc (a2: ptr pfring; a3: cstring): cint {.cdecl.} # DNA only
    dna_init*: proc (a2: ptr pfring): cint {.cdecl.}
    dna_term*: proc (a2: ptr pfring) {.cdecl.}
    dna_enable*: proc (a2: ptr pfring): cint {.cdecl.}
    dna_check_packet_to_read*: proc (a2: ptr pfring; a3: uint8): uint8 {.
        cdecl.}
    dna_next_packet*: proc (a2: ptr pfring; a3: ptr cstring; a4: u_int;
                            a5: ptr pfring_pkthdr): ptr cstring {.cdecl.}
    dna_get_num_tx_slots*: proc (ring: ptr pfring): u_int {.cdecl.}
    dna_get_num_rx_slots*: proc (ring: ptr pfring): u_int {.cdecl.}
    dna_get_next_free_tx_slot*: proc (ring: ptr pfring): u_int {.cdecl.}
    dna_copy_tx_packet_into_slot*: proc (ring: ptr pfring;
        tx_slot_id: uint32; buffer: cstring; len: u_int): ptr cstring {.cdecl.}
    dna_tx_ready*: proc (a2: ptr pfring): uint8 {.cdecl.} # Silicom Redirector Only
    rdi*: INNER_C_STRUCT_6977292814936016408
    ft_mode*: filtering_mode
    ft_device_type*: pfring_device_type # All devices
    buffer*: cstring
    slots*: cstring
    device_name*: cstring
    caplen*: uint32
    slot_header_len*: uint16
    mtu_len*: uint16       # 0 = unknown
    sampling_rate*: uint32
    sampling_counter*: uint32
    kernel_packet_consumer*: uint8
    is_shutting_down*: uint8
    socket_default_accept_policy*: uint8
    fd*: cint
    device_id*: cint
    slots_info*: ptr FlowSlotInfo
    poll_sleep*: u_int
    poll_duration*: uint16
    promisc*: uint8
    clear_promisc*: uint8
    reentrant*: uint8
    break_recv_loop*: uint8
    num_poll_calls*: culong
    rx_lock*: pthread_rwlock_t
    tx_lock*: pthread_rwlock_t
    sock_tx*: sockaddr_ll     # Reflector socket (copy RX packets onto it)
    reflector_socket*: ptr pfring # Semi-ZC/DNA devices (1-copy)
    one_copy_rx_pfring*: ptr pfring

# *********************************

const
  MAX_NUM_BUNDLE_ELEMENTS* = 32

type
  pfringProcesssPacket* = proc (h: ptr pfring_pkthdr, p: ptr cstring, user_bytes: ptr cstring) {.cdecl.}

  bundle_read_policy* {.size: sizeof(cint).} = enum
    pick_round_robin = 0, pick_fifo
  pfring_bundle* = object
    policy*: bundle_read_policy
    num_sockets*: uint16
    last_read_socket*: uint16
    sockets*: array[MAX_NUM_BUNDLE_ELEMENTS, ptr pfring]
    pfd*: array[MAX_NUM_BUNDLE_ELEMENTS, pollfd]



# *********************************

const
  PF_RING_ZC_SYMMETRIC_RSS* = (1 shl 0) #*< pfring_open() flag: Set the hw RSS function to symmetric mode (both directions of the same flow go to the same hw queue). Supported by ZC/DNA drivers only. This option is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_DNA_RSS environment variable.
  PF_RING_REENTRANT* = (1 shl 1) #*< pfring_open() flag: The device is open in reentrant mode. This is implemented by means of semaphores and it results is slightly worse performance. Use reentrant mode only for multithreaded applications.
  PF_RING_LONG_HEADER* = (1 shl 2) #*< pfring_open() flag: If uset, PF_RING does not fill the field extended_hdr of struct pfring_pkthdr. If set, the extended_hdr field is also properly filled. In case you do not need extended information, set this value to 0 in order to speedup the operation.
  PF_RING_PROMISC* = (1 shl 3) #*< pfring_open() flag: The device is open in promiscuous mode.
  PF_RING_TIMESTAMP* = (1 shl 4) #*< pfring_open() flag: Force PF_RING to set the timestamp on received packets (usually it is not set when using zero-copy, for optimizing performance).
  PF_RING_HW_TIMESTAMP* = (1 shl 5) #*< pfring_open() flag: Enable hw timestamping, when available.
  PF_RING_RX_PACKET_BOUNCE* = (1 shl 6) #*< pfring_open() flag: Enable fast forwarding support (see pfring_send_last_rx_packet()).
  PF_RING_ZC_FIXED_RSS_Q_0* = (1 shl 7) #*< pfring_open() flag: Set hw RSS to send all traffic to queue 0. Other queues can be selected using hw filters (ZC/DNA cards with hw filtering only).
  PF_RING_STRIP_HW_TIMESTAMP* = (1 shl 8) #*< pfring_open() flag: Strip hw timestamp from the packet.
  PF_RING_DO_NOT_PARSE* = (1 shl 9) #*< pfring_open() flag: Disable packet parsing also when 1-copy is used. (parsing already disabled in zero-copy)
  PF_RING_DO_NOT_TIMESTAMP* = (1 shl 10) #*< pfring_open() flag: Disable packet timestamping also when 1-copy is used. (sw timestamp already disabled in zero-copy)
  PF_RING_CHUNK_MODE* = (1 shl 11) #*< pfring_open() flag: Enable chunk mode operations. This mode is supported only by specific adapters and it's not for general purpose.
  PF_RING_IXIA_TIMESTAMP* = (1 shl 12) #*< pfring_open() flag: Enable ixiacom.com hardware timestamp support+stripping.
  PF_RING_USERSPACE_BPF* = (1 shl 13) #*< pfring_open() flag: Force userspace bpf even with standard drivers (not only with ZC/DNA).
  PF_RING_ZC_NOT_REPROGRAM_RSS* = (1 shl 14) #*< pfring_open() flag: Do not touch/reprogram hw RSS
  PF_RING_VSS_APCON_TIMESTAMP* = (1 shl 15) #*< pfring_open() flag: Enable apcon.com/vssmonitoring.com hardware timestamp support+stripping.
  PF_RING_ZC_IPONLY_RSS* = (1 shl 16) #*< pfring_open() flag: Compute RSS on src/dst IP only (not 4-tuple)

# *********************************
# backward compatibility

const
  PF_RING_DNA_SYMMETRIC_RSS* = PF_RING_ZC_SYMMETRIC_RSS
  PF_RING_DNA_FIXED_RSS_Q_0* = PF_RING_ZC_FIXED_RSS_Q_0

# *********************************
#*
#  This call is used to initialize a PF_RING socket hence obtain a handle of type struct pfring
#  that can be used in subsequent calls. Note that:
#  1. you can use physical (e.g. ethX) and virtual (e.g. tapX) devices, RX-queues (e.g. ethX@Y),
#     and additional modules (e.g. dna:dnaX@Y, dag:dagX:Y, "multi:ethA@X;ethB@Y;ethC@Z", "dnacluster:A@X", "stack:dnaX").
#  2. you need super-user capabilities in order to open a device.
#  @param device_name Symbolic name of the PF_RING-aware device we’re attempting to open (e.g. eth0).
#  @param caplen      Maximum packet capture len (also known as snaplen).
#  @param flags       It allows several options to be specified on a compact format using bitmaps (see PF_RING_* macros).
#  @return On success a handle is returned, NULL otherwise.
#

proc pfring_open*(device_name: cstring; caplen: uint32; flags: uint32): ptr pfring {.pfring.}
#*
#  Same as pfring_open(), but initializes a kernel plugin for packet processing.
#  @param device_name
#  @param caplen
#  @param flags
#  @param consumer_plugin_id The plugin id.
#  @param consumer_data      The plugin data.
#  @param consumer_data_len  The size of the plugin data.
#  @return On success a handle is returned, NULL otherwise.
#

proc pfring_open_consumer*(device_name: cstring; caplen: uint32;
                           flags: uint32; consumer_plugin_id: uint8;
                           consumer_data: cstring; consumer_data_len: u_int): ptr pfring {.pfring.}
#*
#  This call is similar to pfring_open() with the exception that in case of a multi RX-queue NIC,
#  instead of opening a single ring for the whole device, several individual rings are open (one per RX-queue).
#  @param device_name Symbolic name of the PF_RING-aware device we’re attempting to open (e.g. eth0).
#                     No queue name hash to be specified, but just the main device name.
#  @param caplen      Maximum packet capture len (also known as snaplen).
#  @param flags       See pfring_open() for details.
#  @param ring        A pointer to an array of rings that will contain the opened ring pointers.
#  @return The last index of the ring array that contain a valid ring pointer.
#

proc pfring_open_multichannel*(device_name: cstring; caplen: uint32;
                               flags: uint32;
                               ring: array[32, ptr pfring]): uint8 {.
    cdecl, importc: "pfring_open_multichannel".}
#*
#  Shutdown a socket.
#  @param ring The PF_RING handle.
#

proc pfring_shutdown*(ring: ptr pfring) {.pfring.}
#*
#  Set the scheduler priority for the current thread.
#  @param cpu_percentage The priority.
#

proc pfring_config*(cpu_percentage: cushort) {.pfring.}
#*
#  Process ingress packets until pfring_breakloop() is called, or an error occurs.
#  @param ring            The PF_RING handle.
#  @param looper          The user callback for packet processing.
#  @param user_bytes      The user ptr passed to the callback.
#  @param wait_for_packet If 0 active wait is used to check the packet availability.
#  @return 0 on success (pfring_breakloop()), a negative value otherwise.
#
proc pfring_loop*(ring: ptr pfring; looper: proc (h: ptr pfring_pkthdr, p: cstring, user_bytes: ptr cstring) {.cdecl.}; #pfringProcesssPacket;
                  user_bytes: ptr cstring; wait_for_packet: uint8): cint {.pfring.}

#*
#  Break a receive loop (pfring_loop() or blocking pfring_recv()).
#  @param ring The PF_RING handle.
#

proc pfring_breakloop*(a2: ptr pfring) {.pfring.}
#*
#  This call is used to terminate an PF_RING device previously open.
#  Note that you must always close a device before leaving an application. If unsure, you can close a device from a signal handler.
#  @param ring The PF_RING handle that we are attempting to close.
#

proc pfring_close*(ring: ptr pfring) {.pfring.}
#*
#  Read ring statistics (packets received and dropped).
#  @param ring  The PF_RING handle.
#  @param stats A user-allocated buffer on which stats (number of received and dropped packets) will be stored.
#  @return 0 on uccess, a negative value otherwise.
#

proc pfring_stats*(ring: ptr pfring; stats: ptr pfring_stat): cint {.pfring.}
#*
#  This call returns an incoming packet when available.
#  @param ring       The PF_RING handle where we perform the check.
#  @param buffer     A memory area allocated by the caller where the incoming packet will be stored.
#                    Note that this parameter is a pointer to a pointer, in order to enable zero-copy implementations (buffer_len must be set to 0).
#  @param buffer_len The length of the memory area above.
#                    Note that the incoming packet is cut if it is too long for the allocated area.
#                    A length of 0 indicates to use the zero-copy optimization, when available.
#  @param hdr        A memory area where the packet header will be copied.
#  @param wait_for_incoming_packet If 0 we simply check the packet availability, otherwise the call is blocked until a packet is available.
#                    This option is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_ACTIVE_POLL environment variable.
#  @return 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.
#

proc pfring_recv*(ring: ptr pfring; buffer: ptr cstring; buffer_len: u_int;
                  hdr: ptr pfring_pkthdr; wait_for_incoming_packet: uint8): cint {.pfring.}
#*
#  Same of pfring_recv(), with additional parameters to force packet parsing.
#  @param ring
#  @param buffer
#  @param buffer_len
#  @param hdr
#  @param wait_for_incoming_packet
#  @param level         The header level where to stop parsing.
#  @param add_timestamp Add the timestamp.
#  @param add_hash      Compute an IP-based bidirectional hash.
#  @return 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.
#

proc pfring_recv_parsed*(ring: ptr pfring; buffer: ptr cstring;
                         buffer_len: u_int; hdr: ptr pfring_pkthdr;
                         wait_for_incoming_packet: uint8; level: uint8; #
                                                                              # 1..4
                         add_timestamp: uint8; add_hash: uint8): cint {.pfring.}
#*
#  Whenever a user-space application has to wait until incoming packets arrive, it can instruct PF_RING not to return from poll() call
#  unless at least “watermark” packets have been returned. A low watermark value such as 1, reduces the latency of poll() but likely
#  increases the number of poll() calls. A high watermark (it cannot exceed 50% of the ring size, otherwise the PF_RING kernel module
#  will top its value) instead reduces the number of poll() calls but slightly increases the packet latency.
#  The default value for the watermark (i.e. if user-space applications do not manipulate is value via this call) is 128.
#  @param ring      The PF_RING handle to enable.
#  @param watermark The packet poll watermark.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_poll_watermark*(ring: ptr pfring; watermark: uint16): cint {.
    cdecl, importc: "pfring_set_poll_watermark".}
#*
#  Set the poll timeout when passive wait is used.
#  @param ring     The PF_RING handle to enable.
#  @param duration The poll timeout in msec.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_poll_duration*(ring: ptr pfring; duration: u_int): cint {.cdecl,
    importc: "pfring_set_poll_duration".}
#*
#  Set the number of packets that have to be enqueued in the egress queue before being sent on the wire.
#  @param ring      The PF_RING handle to enable.
#  @param watermark The tx watermark.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_tx_watermark*(ring: ptr pfring; watermark: uint16): cint {.
    cdecl, importc: "pfring_set_tx_watermark".}
#*
#  Set a specified filtering rule into the NIC. Note that no PF_RING filter is added, but only a NIC filter.
#
#  Some multi-queue modern network adapters feature "packet steering" capabilities. Using them it is possible to
#  instruct the hardware NIC to assign selected packets to a specific RX queue. If the specified queue has an Id
#  that exceeds the maximum queueId, such packet is discarded thus acting as a hardware firewall filter.
#  Note: kernel packet filtering is not supported by ZC/DNA.
#  @param ring The PF_RING handle on which the rule will be added.
#  @param rule The filtering rule to be set in the NIC as defined in the last chapter of this document.
#              All rule parameters should be defined, and if set to zero they do not participate to filtering.
#  @return 0 on success, a negative value otherwise (e.g. the rule to be added has wrong format or if the NIC to
#          which this ring is bound does not support hardware filters).
#

proc pfring_add_hw_rule*(ring: ptr pfring; rule: ptr hw_filtering_rule): cint {.
    cdecl, importc: "pfring_add_hw_rule".}
#*
#  Remove the specified filtering rule from the NIC.
#  @param ring The PF_RING handle on which the rule will be removed.
#  @param rule The filtering rule to be removed from the NIC.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_remove_hw_rule*(ring: ptr pfring; rule_id: uint16): cint {.cdecl,
    importc: "pfring_remove_hw_rule".}
#*
#  Set the device channel id to be used.
#  @param ring       The PF_RING handle.
#  @param channel_id The channel id.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_channel_id*(ring: ptr pfring; channel_id: uint32): cint {.
    cdecl, importc: "pfring_set_channel_id".}
#*
#  Set the channel mask to be used for packet capture.
#  @param ring         The PF_RING handle.
#  @param channel_mask The channel mask.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_channel_mask*(ring: ptr pfring; channel_mask: uint64): cint {.
    cdecl, importc: "pfring_set_channel_mask".}
#*
#  Tell PF_RING the name of the application (usually argv[0]) that uses this ring. This information is used to identify the application
#  when accessing the files present in the PF_RING /proc filesystem.
#  This is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_APPNAME environment variable.
#  Example:
#  $ cat /proc/net/pf_ring/16614-eth0.0 | grep Name
#  Appl. Name     : pfcount
#  @param ring The PF_RING handle to enable.
#  @param name The name of the application using this ring.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_application_name*(ring: ptr pfring; name: cstring): cint {.pfring.}
#*
#  Set custom application statistics.
#  @param ring The PF_RING handle.
#  @param stats The application stats.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_application_stats*(ring: ptr pfring; stats: cstring): cint {.
    cdecl, importc: "pfring_set_application_stats".}
#*
#  Return the filename where the application statistics can be read.
#  @param ring     The PF_RING handle.
#  @param path     A user-allocated buffer on which the stats filename will be stored.
#  @param path_len The path len.
#  @return The path if success, NULL otherwise.
#

proc pfring_get_appl_stats_file_name*(ring: ptr pfring; path: cstring;
                                      path_len: u_int): cstring {.cdecl,
    importc: "pfring_get_appl_stats_file_name".}
#*
#  Bind a socket to a device.
#  @param ring        The PF_RING handle.
#  @param device_name The device name.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_bind*(ring: ptr pfring; device_name: cstring): cint {.cdecl,
    importc: "pfring_bind".}
#*
#  Send a raw packet (i.e. it is sent on wire as specified). This packet must be fully specified (the MAC address up)
#  and it will be transmitted as-is without any further manipulation.
#
#  Depending on the driver being used, packet transmission happens differently:
#  - Vanilla and PF_RING aware drivers: PF_RING does not accelerate the TX so the standard Linux transmission facilities are used.
#    Do not expect speed advantage when using PF_RING in this mode.
#  - ZC/DNA: line rate transmission is supported.
#  @param ring         The PF_RING handle on which the packet has to be sent.
#  @param pkt          The buffer containing the packet to send.
#  @param pkt_len      The length of the pkt buffer.
#  @param flush_packet 1 = Flush possible transmission queues. If set to 0, you will decrease your CPU usage but at the cost of
#                      sending packets in trains and thus at larger latency.
#  @return The number of bytes sent if success, a negative value otherwise.
#

proc pfring_send*(ring: ptr pfring; pkt: cstring; pkt_len: u_int;
                  flush_packet: uint8): cint {.pfring.}
#*
#  Same as pfring_send(), with the possibility to specify the outgoing interface index.
#  @param ring
#  @param pkt
#  @param pkt_len
#  @param flush_packet
#  @param if_index     The interface index assigned to the outgoing device.
#  @return The number of bytes sent if success, a negative value otherwise.
#

proc pfring_send_ifindex*(ring: ptr pfring; pkt: cstring; pkt_len: u_int;
                          flush_packet: uint8; if_index: cint): cint {.cdecl,
    importc: "pfring_send_ifindex".}
#*
#  Same as pfring_send(), but this function allows to send a raw packet returning the exact time (ns) it has been sent on the wire.
#  Note that this is available when the adapter supports tx hardware timestamping only and might affect performance.
#  @param ring
#  @param pkt
#  @param pkt_len
#  @param ts      The struct where the tx timestamp will be stored.
#  @return The number of bytes sent if success, a negative value otherwise.
#

proc pfring_send_get_time*(ring: ptr pfring; pkt: cstring; pkt_len: u_int;
                           ts: ptr Timespec): cint {.cdecl,
    importc: "pfring_send_get_time".}
#*
#  Returns the number of RX channels (also known as RX queues) of the ethernet interface to which this ring is bound.
#  @param ring The PF_RING handle to query.
#  @return The number of RX channels, or 1 (default) in case this in information is unknown.
#

proc pfring_get_num_rx_channels*(ring: ptr pfring): uint8 {.cdecl,
    importc: "pfring_get_num_rx_channels".}
#*
#  Implement packet sampling directly into the kernel. Note that this solution is much more efficient than implementing it in user-space.
#  Sampled packets are only those that pass all filters (if any).
#  @param ring The PF_RING handle on which sampling is applied.
#  @param rate The sampling rate. Rate of X means that 1 packet out of X is forwarded. This means that a sampling rate of 1 disables sampling.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_sampling_rate*(ring: ptr pfring; rate: uint32): cint {.pfring.}
  # 1 = no sampling
#*
#  Returns the file descriptor associated to the specified ring.
#  This number can be used in function calls such as poll() and select() for passively waiting for incoming packets.
#  @param ring The PF_RING handle to query.
#  @return A number that can be used as reference to this ring, in function calls that require a selectable file descriptor.
#

proc pfring_get_selectable_fd*(ring: ptr pfring): cint {.cdecl,
    importc: "pfring_get_selectable_fd".}
#*
#  Tell PF_RING to consider only those packets matching the specified direction. If the application does not call this function,
#  all the packets (regardless of the direction, either RX or TX) are returned.
#  @param ring      The PF_RING handle to enable.
#  @param direction The packet direction (RX, TX or both RX and TX).
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_direction*(ring: ptr pfring; direction: packet_direction): cint {.pfring.}
#*
#  Tell PF_RING if the application needs to send and/or receive packets to/from the socket.
#  @param ring The PF_RING handle to enable.
#  @param mode The socket mode (send, receive or both send and receive).
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_socket_mode*(ring: ptr pfring; mode: socket_mode): cint {.pfring.}
#*
#  This call allows a ring to be added to a cluster that can spawn across address spaces.
#  On a nuthsell when two or more sockets are clustered they share incoming packets that are balanced on a per-flow manner.
#  This technique is useful for exploiting multicore systems of for sharing packets in the same address space across multiple threads.
#  Clustering is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_CLUSTER_ID environment variable (Round-Robin by default,
#  per-flow via the PCAP_PF_RING_USE_CLUSTER_PER_FLOW environment variable).
#  @param ring The  PF_RING handle to be cluster.
#  @param clusterId A numeric identifier of the cluster to which the ring will be bound.
#  @param the_type  The cluster type (2-tuple, 4-tuple, 5-tuple, tcp only 5-tuple, 6-tuple flow or Round-Robin).
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_cluster*(ring: ptr pfring; clusterId: u_int;
                         the_type: cluster_type): cint {.pfring.}
#*
#  This call allows a ring to be removed from a previous joined cluster.
#  @param ring      The PF_RING handle to be cluster.
#  @param clusterId A numeric identifier of the cluster to which the ring will be bound.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_remove_from_cluster*(ring: ptr pfring): cint {.pfring.}
#*
#  Set the master ring using the id (vanilla PF_RING only)
#  @param ring   The PF_RING handle.
#  @param master The master socket id.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_master_id*(ring: ptr pfring; master_id: uint32): cint {.
    cdecl, importc: "pfring_set_master_id".}
#*
#  Set the master ring using the PF_RING handle (vanilla PF_RING only).
#  @param ring   The PF_RING handle.
#  @param master The master PF_RING handle.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_master*(ring: ptr pfring; master: ptr pfring): cint {.cdecl,
    importc: "pfring_set_master".}
#*
#  Return the ring id.
#  @param ring The PF_RING handle.
#  @return The ring id.
#

proc pfring_get_ring_id*(ring: ptr pfring): uint16 {.cdecl,
    importc: "pfring_get_ring_id".}
#*
#  Return an estimation of the enqueued packets.
#  @param ring The PF_RING handle.
#  @param
#  @return 0 on success, a negative value otherwise.
#

proc pfring_get_num_queued_pkts*(ring: ptr pfring): uint32 {.cdecl,
    importc: "pfring_get_num_queued_pkts".}
#*
#  Return the identifier of the kernel plugin responsible for consuming packets.
#  @param ring The PF_RING handle.
#  @return The kernel plugin identifier.
#

proc pfring_get_packet_consumer_mode*(ring: ptr pfring): uint8 {.cdecl,
    importc: "pfring_get_packet_consumer_mode".}
#*
#  Initialize the kernel plugin for packet processing.
#  @param ring The PF_RING handle.
#  @param plugin_id       The plugin id.
#  @param plugin_data     The plugin data.
#  @param plugin_data_len The size of the plugin data.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_packet_consumer_mode*(ring: ptr pfring; plugin_id: uint8;
                                      plugin_data: cstring;
                                      plugin_data_len: u_int): cint {.cdecl,
    importc: "pfring_set_packet_consumer_mode".}
#*
#  Add or remove a hash filtering rule.
#  All rule parameters should be defined in the filtering rule (no wildcards).
#  @param ring        The PF_RING handle from which stats will be read.
#  @param rule_to_add The rule that will be added/removed as defined in the last chapter of this document.
#                     All rule parameters should be defined in the filtering rule (no wildcards).
#  @param add_rule    If set to a positive value the rule is added, if zero the rule is removed.
#  @return 0 on success, a negative value otherwise (e.g. the rule to be removed does not exist).
#

proc pfring_handle_hash_filtering_rule*(ring: ptr pfring;
                                        rule_to_add: ptr hash_filtering_rule;
                                        add_rule: cstring): cint {.cdecl,
    importc: "pfring_handle_hash_filtering_rule".}
#*
#  Add a wildcard filtering rule to an existing ring. Each rule will have a unique rule Id across the ring (i.e. two rings can have rules with the same id).
#
#  PF_RING allows filtering packets in two ways: precise (a.k.a. hash filtering) or wildcard filtering.
#  Precise filtering is used when it is necessary to track a precise 6-tuple connection <vlan Id, protocol, source IP, source port, destination IP, destination port>.
#  Wildcard filtering is used instead whenever a filter can have wildcards on some of its fields (e.g. match all UDP packets regardless of their destination).
#  If some field is set to zero it will not participate in filter calculation.
#
#  Note about packet reflection: packet reflection is the ability to bridge packets in kernel without sending them to userspace and back.
#  You can specify packet reflection inside the filtering rules.
#
#  typedef struct {
#   ...
#  char reflector_device_name[REFLECTOR_NAME_LEN];
#  ...
#  } filtering_rule;
#
#  In the reflector_device_name you need to specify a device name (e.g. eth0) on which packets matching the filter will be reflected.
#  Make sure NOT to specify as reflection device the same device name on which you capture packets, as otherwise you will create a packet loop.
#
#  @param ring        The PF_RING handle on which the rule will be added.
#  @param rule_to_add The rule to add as defined in the last chapter of this document.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_add_filtering_rule*(ring: ptr pfring;
                                rule_to_add: ptr filtering_rule): cint {.cdecl,
    importc: "pfring_add_filtering_rule".}
#*
#  Remove a previously added filtering rule.
#  @param ring    The PF_RING handle on which the rule will be removed.
#  @param rule_id The id of a previously added rule that will be removed.
#  @return 0 on success, a negative value otherwise (e.g. the rule does not exist).
#

proc pfring_remove_filtering_rule*(ring: ptr pfring; rule_id: uint16): cint {.
    cdecl, importc: "pfring_remove_filtering_rule".}
#*
#  Remove hash filtering rules inactive for the specified number of seconds.
#  @param ring           The PF_RING handle on which the rules will be removed.
#  @param inactivity_sec The inactivity threshold.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_purge_idle_hash_rules*(ring: ptr pfring; inactivity_sec: uint16): cint {.
    cdecl, importc: "pfring_purge_idle_hash_rules".}
#*
#  Remove filtering rules inactive for the specified number of seconds.
#  @param ring           The PF_RING handle on which the rules will be removed.
#  @param inactivity_sec The inactivity threshold.
#  @return 0 on success, a negative value otherwise
#

proc pfring_purge_idle_rules*(ring: ptr pfring; inactivity_sec: uint16): cint {.
    cdecl, importc: "pfring_purge_idle_rules".}
#*
#  Read statistics of a hash filtering rule.
#  @param ring      The PF_RING handle on which the rule will be added/removed.
#  @param rule      The rule for which stats are read. This needs to be the same rule that has been previously added.
#  @param stats     A buffer allocated by the user that will contain the rule statistics.
#                   Please make sure that the buffer is large enough to contain the statistics.
#                   Such buffer will contain number of received and dropped packets.
#  @param stats_len The size (in bytes) of the stats buffer.
#  @return 0 on success, a negative value otherwise (e.g. the rule to be removed does not exist).
#

proc pfring_get_hash_filtering_rule_stats*(ring: ptr pfring;
    rule: ptr hash_filtering_rule; stats: cstring; stats_len: ptr u_int): cint {.
    cdecl, importc: "pfring_get_hash_filtering_rule_stats".}
#*
#  Read statistics of a hash filtering rule.
#  @param ring      The PF_RING handle from which stats will be read.
#  @param rule_id   The rule id that identifies the rule for which stats are read.
#  @param stats     A buffer allocated by the user that will contain the rule statistics.
#                   Please make sure that the buffer is large enough to contain the statistics.
#                   Such buffer will contain number of received and dropped packets.
#  @param stats_len The size (in bytes) of the stats buffer.
#  @return 0 on success, a negative value otherwise (e.g. the rule does not exist).
#

proc pfring_get_filtering_rule_stats*(ring: ptr pfring; rule_id: uint16;
                                      stats: cstring; stats_len: ptr u_int): cint {.
    cdecl, importc: "pfring_get_filtering_rule_stats".}
#*
#  Set the default filtering policy. This means that if no rule is matching the incoming packet the default policy will decide
#  if the packet is forwarded to user space or dropped. Note that filtering rules are limited to a ring, so each ring can have
#  a different set of rules and default policy.
#  @param ring The PF_RING handle on which the rule will be added/removed.
#  @param rules_default_accept_policy If set to a positive value the default policy is accept (i.e. forward packets to user space), drop otherwise.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_toggle_filtering_policy*(ring: ptr pfring;
                                     rules_default_accept_policy: uint8): cint {.
    cdecl, importc: "pfring_toggle_filtering_policy".}
#*
#  Tells PF_RING to rehash incoming packets using a bi-directional hash function.
#  This is also available with the PF_RING-aware libpcap via the PCAP_PF_RING_RSS_REHASH environment variable.
#  @param ring The PF_RING handle to query.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_enable_rss_rehash*(ring: ptr pfring): cint {.cdecl,
    importc: "pfring_enable_rss_rehash".}
#*
#  Performs passive wait on a PF_RING socket, similar to the standard poll(), taking care of data structures synchronization.
#  @param ring          The PF_RING socket to poll.
#  @param wait_duration The poll timeout in msec.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_poll*(ring: ptr pfring; wait_duration: u_int): cint {.cdecl,
    importc: "pfring_poll".}
#*
#  Check if a packet is available.
#  @param ring The PF_RING handle.
#  @return 1 if a packet is available, 0 otherwise.
#

proc pfring_is_pkt_available*(ring: ptr pfring): cint {.cdecl,
    importc: "pfring_is_pkt_available".}
#*
#  This call returns the arrival time of the next incoming packet, when available.
#  @param ring The PF_RING handle where we perform the check.
#  @param ts   The struct where the time will be stored.
#  @return 0 in case of success, a negative number in case of error.
#

proc pfring_next_pkt_time*(ring: ptr pfring; ts: ptr Timespec): cint {.cdecl,
    importc: "pfring_next_pkt_time".}
#*
#  This call returns the raw timestamp of the next incoming packet, when available. This is available with adapters supporting rx hardware timestamping only.
#  @param ring         The PF_RING handle where we perform the check.
#  @param timestamp_ns Where the timestamp will be stored.
#  @return 0 in case of success, a negative number in case of error.
#

proc pfring_next_pkt_raw_timestamp*(ring: ptr pfring;
                                    timestamp_ns: ptr uint64): cint {.cdecl,
    importc: "pfring_next_pkt_raw_timestamp".}
#*
#  Read the ring version. Note that if the ring version is 5.6 the retuned ring version is 0x050600.
#  @param ring    The PF_RING handle to enable.
#  @param version A user-allocated buffer on which ring version will be copied.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_version*(ring: ptr pfring; version: ptr uint32): cint {.cdecl,
    importc: "pfring_version".}
#*
#  Set a reflector device to send all incoming packets. This open a new socket and packets are automatically sent using pfring_send().
#  @param ring        The PF_RING handle.
#  @param device_name The device name.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_reflector_device*(ring: ptr pfring; device_name: cstring): cint {.
    cdecl, importc: "pfring_set_reflector_device".}
#*
#  Returns the MAC address of the device bound to the socket.
#  @param ring        The PF_RING handle to query.
#  @param mac_address The memory area where the MAC address will be copied.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_get_bound_device_address*(ring: ptr pfring;
                                      mac_address: array[6, cstring]): cint {.
    cdecl, importc: "pfring_get_bound_device_address".}
#*
#  Return the size of the PF_RING packet header (vanilla PF_RING only).
#  @param ring The PF_RING handle.
#  @return The size of the packet header.
#

proc pfring_get_slot_header_len*(ring: ptr pfring): uint16 {.cdecl,
    importc: "pfring_get_slot_header_len".}
#*
#  Returns the interface index of the device bound to the socket.
#  @param ring     The PF_RING handle to query.
#  @param if_index The memory area where the interface index will be copied
#  @return 0 on success, a negative value otherwise.
#

proc pfring_get_bound_device_ifindex*(ring: ptr pfring; if_index: ptr cint): cint {.
    cdecl, importc: "pfring_get_bound_device_ifindex".}
#*
#  Return the interface index of the provided device.
#  @param ring        The PF_RING handle.
#  @param device_name The device name.
#  @param if_index    The memory area for storing the interface index.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_get_device_ifindex*(ring: ptr pfring; device_name: cstring;
                                if_index: ptr cint): cint {.cdecl,
    importc: "pfring_get_device_ifindex".}
#*
#  Set a filtering device.
#  @param ring The PF_RING handle.
#  @param info The filtering device info.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_virtual_device*(ring: ptr pfring;
                                info: ptr virtual_filtering_device_info): cint {.
    cdecl, importc: "pfring_set_virtual_device".}
#*
#  This call processes packets until pfring_breakloop() is called or an error occurs.
#  @param ring            The PF_RING handle.
#  @param looper          A callback to be called for each received packet. The parameters passed to this routine are:
#                         a pointer to a struct pfring_pkthdr, a pointer to the packet memory, and a pointer to user_bytes.
#  @param user_bytes      A pointer to user’s data which is passed to the callback.
#  @param wait_for_packet If 0 active wait is used to check the packet availability.
#  @return A non-negative number if pfring_breakloop() is called. A negative number in case of error.
#

proc pfring_loopback_test*(ring: ptr pfring; buffer: cstring; buffer_len: u_int;
                           test_len: u_int): cint {.cdecl,
    importc: "pfring_loopback_test".}
#*
#  When a ring is created, it is not enabled (i.e. incoming packets are dropped) until the above function is called.
#  @param ring The PF_RING handle to enable.
#  @return 0 on success, a negative value otherwise (e.g. the ring cannot be enabled).
#

proc pfring_enable_ring*(ring: ptr pfring): cint {.pfring.}
#*
#  Disable a ring.
#  @param ring The PF_RING handle to disable.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_disable_ring*(ring: ptr pfring): cint {.pfring.}
#*
#  In order to set BPF filters through the PF_RING API it’s necessary to enable (this is the default) BPF support
#  at compile time and link PF_RING-enabled applications against the -lpcap library (it is possible to disable the
#  BPF support with "cd userland/lib/; ./configure --disable-bpf; make" to avoid linking libpcap).
#  @param ring          The PF_RING handle on which the filter will be set.
#  @param filter_buffer The filter to set.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_bpf_filter*(ring: ptr pfring; filter_buffer: cstring): cint {.pfring.}
#*
#  Remove the BPF filter.
#  @param ring The PF_RING handle.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_remove_bpf_filter*(ring: ptr pfring): cint {.pfring.}
#*
#  Sets the filtering mode (software only, hardware only, both software and hardware) in order to implicitly
#  add/remove hardware rules by means of the same API functionality used for software (wildcard and hash) rules.
#  @param ring The PF_RING handle on which the rule will be removed.
#  @param mode The filtering mode.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_filtering_mode*(ring: ptr pfring; mode: filtering_mode): cint {.
    cdecl, importc: "pfring_set_filtering_mode".}
#*
#  Reads the time from the device hardware clock, when the adapter supports hardware timestamping.
#  @param ring The PF_RING handle.
#  @param ts   The struct where time will be stored.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_get_device_clock*(ring: ptr pfring; ts: ptr Timespec): cint {.cdecl,
    importc: "pfring_get_device_clock".}
#*
#  Sets the time in the device hardware clock, when the adapter supports hardware timestamping.
#  @param ring The PF_RING handle.
#  @param ts   The time to be set.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_device_clock*(ring: ptr pfring; ts: ptr Timespec): cint {.cdecl,
    importc: "pfring_set_device_clock".}
#*
#  Adjust the time in the device hardware clock with an offset, when the adapter supports hardware timestamping.
#  @param ring   The PF_RING handle.
#  @param offset The time offset.
#  @param sign   The offset sign.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_adjust_device_clock*(ring: ptr pfring; offset: ptr Timespec;
                                 sign: int8): cint {.cdecl,
    importc: "pfring_adjust_device_clock".}
#*
#  Synchronizes the ingress ring indexes/registers with the kernel.
#  @param ring The PF_RING handle.
#

proc pfring_sync_indexes_with_kernel*(ring: ptr pfring) {.cdecl,
    importc: "pfring_sync_indexes_with_kernel".}
#*
#  Send the last received packet to the specified device. This is an optimization working with standard PF_RING only.
#  @param ring            The PF_RING handle on which the packet has been received.
#  @param tx_interface_id The egress interface index.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_send_last_rx_packet*(ring: ptr pfring; tx_interface_id: cint): cint {.
    cdecl, importc: "pfring_send_last_rx_packet".}
#*
#  Return the link status.
#  @param ring The PF_RING handle.
#  @return 1 if link is up, 0 otherwise.
#

proc pfring_get_link_status*(ring: ptr pfring): cint {.cdecl,
    importc: "pfring_get_link_status".}
#*
#  Return the number of slots in the egress ring.
#  @param ring The PF_RING handle.
#  @return The number of slots.
#

proc pfring_get_num_tx_slots*(ring: ptr pfring): u_int {.cdecl,
    importc: "pfring_get_num_tx_slots".}
#*
#  Return the number of slots in the ingress ring.
#  @param ring The PF_RING handle.
#  @return The number of slots.
#

proc pfring_get_num_rx_slots*(ring: ptr pfring): u_int {.cdecl,
    importc: "pfring_get_num_rx_slots".}
#*
#  Copies a packet into the specified slot of the egress ring.
#  @param ring       The PF_RING handle.
#  @param tx_slot_id The slot index.
#  @param buffer     The packet to copy.
#  @param len        The packet length.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_copy_tx_packet_into_slot*(ring: ptr pfring; tx_slot_id: uint16;
                                      buffer: cstring; len: u_int): cint {.
    cdecl, importc: "pfring_copy_tx_packet_into_slot".}
#*
#  Return the pointer to the buffer pointed by the packet buffer handle.
#  @param ring       The PF_RING handle.
#  @param pkt_handle The packet handle.
#  @return The pointer to the packet buffer.
#

proc pfring_get_pkt_buff_data*(ring: ptr pfring; pkt_handle: ptr pfring_pkt_buff): ptr cstring {.
    cdecl, importc: "pfring_get_pkt_buff_data".}
#*
#  Set the length of the packet. This function call is not necessary unless you want to custom set the packet length, instead of using the size from the received packet.
#  @param ring       The PF_RING handle.
#  @param pkt_handle The packet handle.
#  @param len        The packet length.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_pkt_buff_len*(ring: ptr pfring; pkt_handle: ptr pfring_pkt_buff;
                              len: uint32): cint {.cdecl,
    importc: "pfring_set_pkt_buff_len".}
#*
#  Bind the buffer handle (handling a packet) to an interface id. This function call is useful to specify the egress interface index.
#  @param ring       The PF_RING handle.
#  @param pkt_handle The packet handle.
#  @param if_index   The interface index.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_pkt_buff_ifindex*(ring: ptr pfring;
                                  pkt_handle: ptr pfring_pkt_buff;
                                  if_index: cint): cint {.cdecl,
    importc: "pfring_set_pkt_buff_ifindex".}
#*
#  Add an interface index to the interface indexes bound to the buffer handle. This is used to specify the egress interfaces (fan-out) of a packet buffer.
#  @param ring The PF_RING handle.
#  @param pkt_handle The packet handle.
#  @param if_index   The interface index.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_add_pkt_buff_ifindex*(ring: ptr pfring;
                                  pkt_handle: ptr pfring_pkt_buff;
                                  if_index: cint): cint {.cdecl,
    importc: "pfring_add_pkt_buff_ifindex".}
#*
#  Allocate a packet buffer handle.
#  The memory is allocated by PF_RING into the kernel and it is managed by PF_RING (i.e. no free() on this memory) using the pfring_XXX_XXX calls.
#  @param ring The PF_RING handle.
#  @return The buffer handle.
#

proc pfring_alloc_pkt_buff*(ring: ptr pfring): ptr pfring_pkt_buff {.cdecl,
    importc: "pfring_alloc_pkt_buff".}
#*
#  Release a packet buffer handle previously allocated by pfring_alloc_pkt_buff.
#  @param ring       The PF_RING handle.
#  @param pkt_handle The packet buffer handle.
#

proc pfring_release_pkt_buff*(ring: ptr pfring; pkt_handle: ptr pfring_pkt_buff) {.
    cdecl, importc: "pfring_release_pkt_buff".}
#*
#  Same as pfring_recv(), this function receive a packet filling the buffer pointed by the provided packet handle instead of returning a new buffer.
#  In a nutshell, the returned packet is put on the passed function argument.
#  @param ring       The PF_RING handle.
#  @param pkt_handle The packet buffer handle.
#  @param hdr        The PF_RING header.
#  @param wait_for_incoming_packet If 0 we simply check the packet availability, otherwise the call is blocked until a packet is available.
#  @return 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.
#

proc pfring_recv_pkt_buff*(ring: ptr pfring; pkt_handle: ptr pfring_pkt_buff;
                           hdr: ptr pfring_pkthdr;
                           wait_for_incoming_packet: uint8): cint {.cdecl,
    importc: "pfring_recv_pkt_buff".}
#*
#  Same as pfring_send(), this function send the packet pointed by the provided packet buffer handle.
#  Note: this function resets the content of the buffer handle so if you need to keep its content, make sure you copy the data before you call it.
#  @param ring         The PF_RING handle.
#  @param pkt_handle   The packet buffer handle.
#  @param flush_packet Flush all packets in the transmission queues, if any.
#  @return The number of bytes sent if success, a negative value otherwise.
#

proc pfring_send_pkt_buff*(ring: ptr pfring; pkt_handle: ptr pfring_pkt_buff;
                           flush_packet: uint8): cint {.cdecl,
    importc: "pfring_send_pkt_buff".}
#*
#  Synchronizes the egress ring indexes/registers flushing enqueued packets.
#  @param ring The PF_RING handle.
#  @param
#  @return 0 on success, a negative value otherwise.
#

proc pfring_flush_tx_packets*(ring: ptr pfring): cint {.cdecl,
    importc: "pfring_flush_tx_packets".}
#*
#  Add a string to search in the packet payload (used for filtering).
#  @param ring             The PF_RING handle.
#  @param string_to_search The string to search.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_search_payload*(ring: ptr pfring; string_to_search: cstring): cint {.
    cdecl, importc: "pfring_search_payload".}
#*
#  Attach a DNA socket to a DNA Cluster slave socket, allowing an application receiving packets from a cluster to send them in zero-copy to a DNA interface/queue.
#  @param ring The PF_RING DNA Cluster slave handle.
#  @param ring The PF_RING DNA tx socket that have to be attached to the cluster.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_register_zerocopy_tx_ring*(ring: ptr pfring; tx_ring: ptr pfring): cint {.
    cdecl, importc: "pfring_register_zerocopy_tx_ring".}
# PF_RING Socket bundle
#*
#  Initialize a bundle socket.
#  @param bundle             The PF_RING bundle handle.
#  @param bundle_read_policy The policy for reading ingress packets.
#

proc pfring_bundle_init*(bundle: ptr pfring_bundle; p: bundle_read_policy) {.
    cdecl, importc: "pfring_bundle_init".}
#*
#  Add a ring to a bundle socket.
#  @param bundle The PF_RING bundle handle.
#  @param ring   The PF_RING handle to add.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_bundle_add*(bundle: ptr pfring_bundle; ring: ptr pfring): cint {.
    cdecl, importc: "pfring_bundle_add".}
#*
#  Poll on a bundle socket.
#  @param bundle        The PF_RING bundle handle.
#  @param wait_duration The poll duration.
#  @return The poll return value.
#

proc pfring_bundle_poll*(bundle: ptr pfring_bundle; wait_duration: u_int): cint {.
    cdecl, importc: "pfring_bundle_poll".}
#*
#  Same as pfring_recv() on a bundle socket.
#  @param bundle     The PF_RING bundle handle.
#  @param buffer
#  @param buffer_len
#  @param hdr
#  @param wait_for_incoming_packet
#  @return 0 in case of no packet being received (non-blocking), 1 in case of success, -1 in case of error.
#

proc pfring_bundle_read*(bundle: ptr pfring_bundle; buffer: ptr cstring;
                         buffer_len: u_int; hdr: ptr pfring_pkthdr;
                         wait_for_incoming_packet: uint8): cint {.cdecl,
    importc: "pfring_bundle_read".}
#*
#  Destroy a bundle socket.
#  @param bundle The PF_RING bundle handle.
#

proc pfring_bundle_destroy*(bundle: ptr pfring_bundle) {.cdecl,
    importc: "pfring_bundle_destroy".}
#*
#  Close a bundle socket.
#  @param bundle The PF_RING bundle handle.
#

proc pfring_bundle_close*(bundle: ptr pfring_bundle) {.cdecl,
    importc: "pfring_bundle_close".}
# Utils (defined in pfring_utils.c)
#*
#  Parse a packet.
#  It expects that the hdr memory is either zeroed or contains valid values for the current packet, in order to avoid  parsing twice the same packet headers.
#  This is implemented by controlling the l3_offset and l4_offset fields, indicating that respectively the L2 and L3 layers have been parsed when other than zero.
#  @param pkt           The packet buffer.
#  @param hdr           The header to be filled.
#  @param level         The header level where to stop parsing.
#  @param add_timestamp Add the timestamp.
#  @param add_hash      Compute an IP-based bidirectional hash.
#  @return A non-negative number indicating the topmost header level on success,  a negative value otherwise.
#

proc pfring_parse_pkt*(pkt: cstring; hdr: ptr pfring_pkthdr; level: uint8; #
                                                                                 # 2..4
                       add_timestamp: uint8; # 0,1
                       add_hash: uint8): cint {.pfring.}
  # 0,1
#*
#  Set the promiscuous mode flag to a device.
#  @param device      The device name.
#  @param set_promisc The promisc flag.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_if_promisc*(device: cstring; set_promisc: cint): cint {.cdecl,
    importc: "pfring_set_if_promisc".}
#*
#  Format a number.
#  @param val          The value.
#  @param buf          The destination buffer.
#  @param buf_len      The destination buffer length.
#  @param add_decimals A flag indicating whether to add decimals.
#  @return The produced string.
#

proc pfring_format_numbers*(val: cdouble; buf: cstring; buf_len: u_int;
                            add_decimals: uint8): cstring {.cdecl,
    importc: "pfring_format_numbers".}
#*
#  Enables rx and tx hardware timestamping, when the adapter supports it.
#  @param ring        The PF_RING handle.
#  @param device_name The name of the device where timestamping will be enabled.
#  @param enable_rx   Flag to enable rx timestamping.
#  @param enable_tx   Flag to enable tx timestamping.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_enable_hw_timestamp*(ring: ptr pfring; device_name: cstring;
                                 enable_rx: uint8; enable_tx: uint8): cint {.
    cdecl, importc: "pfring_enable_hw_timestamp".}
#*
#  Return the size of the MTU.
#  @param ring The PF_RING handle.
#  @return The MTU size on success, a negative value otherwise.
#

proc pfring_get_mtu_size*(ring: ptr pfring): cint {.cdecl,
    importc: "pfring_get_mtu_size".}
#*
#  Return NIC settings: max packet length, num rx/tx slots (DNA/ZC only).
#  @param ring     The PF_RING handle.
#  @param settings The card settings (output).
#  @return 0 on success, a negative value otherwise.
#

proc pfring_get_card_settings*(ring: ptr pfring;
                               settings: ptr pfring_card_settings): cint {.
    cdecl, importc: "pfring_get_card_settings".}
#*
#  Print a packet (the header with parsing info must be provided).
#  @param buff     The destination buffer.
#  @param buff_len The destination buffer length.
#  @param p        The packet.
#  @param h        The header.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_print_parsed_pkt*(buff: cstring; buff_len: u_int; p: ptr cstring;
                              h: ptr pfring_pkthdr): cint {.pfring.}
#*
#  Print a packet.
#  @param buff     The destination buffer.
#  @param buff_len The destination buffer length.
#  @param p        The packet.
#  @param caplen   The packet length.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_print_pkt*(buff: cstring; buff_len: u_int; p: ptr cstring;
                       len: u_int; caplen: u_int): cint {.pfring.}
#*
#  Receive a packet chunk, if enabled via pfring_open() flag.
#  @param ring                      The PF_RING handle.
#  @param chunk                     A buffer that will point to the received chunk. Note that the chunk format is adapter specific.
#  @param chunk_len                 Length of the received data chunk.
#  @param wait_for_incoming_chunk   If 0 active wait is used to check the packet availability.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_recv_chunk*(ring: ptr pfring; chunk: ptr pointer;
                        chunk_len: ptr uint32;
                        wait_for_incoming_chunk: uint8): cint {.cdecl,
    importc: "pfring_recv_chunk".}
#*
#  Set a custom device name to which the socket is bound. This function should be called for devices that are not visible via ifconfig
#  @param ring            The PF_RING handle.
#  @param custom_dev_name The custom device name to be used for this socket.
#  @return 0 on success, a negative value otherwise.
#

proc pfring_set_bound_dev_name*(ring: ptr pfring; custom_dev_name: cstring): cint {.
    cdecl, importc: "pfring_set_bound_dev_name".}
#*
#  Reads a IXIA-formatted timestamp from an incoming packet and puts it into the timestamp variable.
#  @param buffer            Incoming packet buffer.
#  @param buffer_len        Incoming packet buffer length.
#  @param ts                If found the hardware timestamp will be placed here
#  @return The length of the IXIA timestamp (hence 0 means that the timestamp has not been found).
#

proc pfring_read_ixia_hw_timestamp*(buffer: ptr cstring; buffer_len: uint32;
                                    ts: ptr Timespec): cint {.cdecl,
    importc: "pfring_read_ixia_hw_timestamp".}
#*
#  Strip a IXIA-formatted timestamp from an incoming packet. If the timestamp is found, the
#  hdr parameter (caplen and len fields) are decreased by the size of the timestamp.
#  @param buffer            Incoming packet buffer.
#  @param hdr               This is an in/out parameter: it is used to read the original packet len, and it is updated (size decreased) if the hw timestamp is found
#  @return 0 on success, a negative value otherwise.
#

proc pfring_handle_ixia_hw_timestamp*(buffer: ptr cstring; hdr: ptr pfring_pkthdr) {.
    cdecl, importc: "pfring_handle_ixia_hw_timestamp".}
#*
#  Reads a VSS/APCON-formatted timestamp from an incoming packet and puts it into the timestamp variable.
#  @param buffer            Incoming packet buffer.
#  @param buffer_len        Incoming packet buffer length.
#  @param ts                If found the hardware timestamp will be placed here
#  @return The length of the VSS/APCON timestamp
#

proc pfring_read_vss_apcon_hw_timestamp*(buffer: ptr cstring;
    buffer_len: uint32; ts: ptr Timespec): cint {.cdecl,
    importc: "pfring_read_vss_apcon_hw_timestamp".}
#*
#  Strip an VSS/APCON-formatted timestamp from an incoming packet. If the timestamp is found, the
#  hdr parameter (caplen and len fields) are decreased by the size of the timestamp.
#  @param buffer            Incoming packet buffer.
#  @param hdr               This is an in/out parameter: it is used to read the original packet len, and it is updated (size decreased) if the hw timestamp is found
#  @return 0 on success, a negative value otherwise.
#

proc pfring_handle_vss_apcon_hw_timestamp*(buffer: ptr cstring;
    hdr: ptr pfring_pkthdr) {.pfring.}
# *********************************

proc pfring_parse_bpf_filter*(filter_buffer: cstring; caplen: u_int;
                              filter: ptr pfring_bpf_program): cint {.cdecl,
    importc: "pfring_parse_bpf_filter".}
proc pfring_free_bpf_filter*(filter: ptr pfring_bpf_program) {.cdecl,
    importc: "pfring_free_bpf_filter".}
