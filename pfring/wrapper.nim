import posix
import times

import types

{.passL: "-lpfring -lpcap -lnuma -lrt".}

{.pragma: pf,
  cdecl,
  importc
.}

proc pfring_open*(device: cstring, caplen, flags: cuint): pfring {.pf.}
proc pfring_open_consumer*(device: cstring, caplen, flags: cuint, cpi: uint8, cd: cstring, cdl: cint): pfring {.pf.}
proc pfring_open_multichannel*(device: cstring, caplen, flags: cuint, rings: array[1..32, pfring]): uint8 {.pf.}
proc pfring_shutdown*(ring: pfring) {.pf.}
proc pfring_config*(cpuPercentage: cshort) {.pf.}
proc pfring_loop*(ring: pfring, looper: pfringProcessPacket, userBytes: cstring, wfp: uint8): cint {.pf.}
proc pfring_breakloop*(ring: pfring) {.pf.}
proc pfring_close*(ring: pfring) {.pf.}
proc pfring_stats*(ring: pfring, stats: pfring_stat): cint {.pf.}
proc pfring_recv*(ring: pfring, buf: ptr, bufLen: int, hdr: pfring_pkthdr, wfip: uint8): cint {.pf.}
proc pfring_recv_parsed*(ring: pfring, buf: pointer, bufLen: cint, hdr: pfring_pkthdr, wfip, level, addTimestamp, addHash: uint8): cint {.pf.}
proc pfring_set_poll_watermark*(ring: pfring, watermark: uint16): cint {.pf.}
proc pfring_set_poll_duration*(ring: pfring, duration: cuint): cint {.pf.}
proc pfring_set_tx_watermark*(ring: pfring, watermark: uint16): cint {.pf.}
proc pfring_add_hw_rule*(rung: pfring, rule: hw_filtering_rule): cint {.pf.}
proc pfring_remove_hw_rule*(ring: pfring, rule_id: uint16): cint {.pf.}
proc pfring_set_channel_id*(ring: pfring, channel_id: uint32): cint {.pf.}
proc pfring_set_channel_mask*(ring: pfring, channel_mask: uint64): cint {.pf.}
proc pfring_set_application_name*(ring: pfring, name: cstring): int {.pf.}
proc pfring_set_application_stats*(ring: pfring, stats: cstring): int {.pf.}
proc pfring_get_appl_stats_file_name*(ring: pfring, path: cstring, path_len: cuint): cstring {.pf.}
proc pfring_bind*(ring: pfring, device: cstring): int {.pf.}
proc pfring_send*(ring: pfring, pkt: cstring, pkt_len: cuint, flush_packet: uint8): int {.pf.}
proc pfring_send_ifindex*(ring: pfring, pkt: cstring, pkt_len: cuint, flush_packet: uint8, if_index: cint): cint {.pf.}
proc pfring_send_get_time*(ring: pfring, pkt: cstring, pkt_len: cuint, ts: Timespec): cint {.pf.}
proc pfring_get_num_rx_channels*(ring: pfring): uint8 {.pf.}
proc pfring_set_sampling_rate*(ring: pfring, rate: uint32): cint {.pf.}
proc pfring_get_selectable_fd*(ring: pfring): cint {.pf.}
proc pfring_set_direction*(ring: pfring, direction: packet_direction): cint {.pf.}
proc pfring_set_socket_mode*(ring: pfring, mode: socket_mode): cint {.pf.}
proc pfring_set_cluster*(ring: pfring, clusterId: cuint, the_type: cluster_type): cint {.pf.}
proc pfring_remove_from_cluster*(ring: pfring): cint {.pf.}
proc pfring_set_master_id*(ring: pfring, master_id: uint32): cint {.pf.}
proc pfring_set_master*(ring, master: pfring): cint {.pf.}
proc pfring_get_ring_id*(ring: pfring): uint16 {.pf.}
proc pfring_get_num_queued_pkts*(ring: pfring): uint32 {.pf.}
proc pfring_get_packet_consumer_mode*(ring: pfring): uint8 {.pf.}
proc pfring_set_packet_consumer_mode*(ring: pfring, plugin_id: uint8, plugin_data: cstring, plugin_data_len: cuint): cint {.pf.}
proc pfring_handle_hash_filtering_rule*(ring: pfring, rta: hash_filtering_rule, add_rule: cuchar): cint {.pf.}
proc pfring_add_filtering_rule*(ring: pfring, rule_to_add: filtering_rule): cint {.pf.}
proc pfring_remove_filtering_rule*(ring: pfring, rule_id: cushort): cint {.pf.}
proc pfring_purge_idle_hash_rules*(ring: pfring, inactivity_sec: cushort): cint {.pf.}
proc pfring_purge_idle_rules*(ring: pfring, inactivity_sec: cushort): cint {.pf.}
proc pfring_get_hash_filtering_rule_stats*(ring: pfring, rule: hash_filtering_rule, stats: cstring, stats_len: cuint): cint {.pf.}
proc pfring_get_filtering_rule_stats*(ring: pfring, rule_id: cushort, stats: cstring, stats_len: cuint): cint {.pf.}
proc pfring_toggle_filtering_policy*(ring: pfring, rules_default_accept_policy: uint8): cint {.pf.}
proc pfring_enable_rss_rehash*(ring: pfring): cint {.pf.}
proc pfring_poll*(ring: pfring, wait_duration: cuint): cint {.pf.}
proc pfring_is_pkt_available*(ring: pfring): cint {.pf.}
proc pfring_next_pkt_time*(ring: pfring, ts: Timespec): cint {.pf.}
proc pfring_next_pkt_raw_timestamp*(ring: pfring, timestamp_ns: uint64): cint {.pf.}
proc pfring_version*(ring: pfring, version: uint32): cint {.pf.}
proc pfring_set_reflector_device*(ring: pfring, device: cstring): cint {.pf.}
proc pfring_get_bound_device_address*(ring: pfring, mac_address: array[1..8, cuchar]): cint {.pf.}
proc pfring_get_slot_header_len*(ring: pfring): cushort {.pf.}
proc pfring_get_bound_device_ifindex*(ring: pfring, if_index: cint): cint {.pf.}
proc pfring_get_device_ifindex*(ring: pfring, device: cstring, if_index: cint): cint {.pf.}
proc pfring_set_virtual_device*(ring: pfring, info: virtual_filtering_device_info): cint {.pf.}
proc pfring_loopback_test*(ring: pfring, buffer: cstring, buffer_len, test_len: cuint): cint {.pf.}
proc pfring_enable_ring*(ring: pfring): cint {.pf.}
proc pfring_disable_ring*(ring: pfring): cint {.pf.}
proc pfring_set_bpf_filter*(ring: pfring, filter_buffer: cstring): cint {.pf.}
proc pfring_remove_bpf_filter*(ring: pfring): cint {.pf.}
proc pfring_set_filtering_mode*(ring: pfring, mode: filtering_mode): cint {.pf.}
proc pfring_get_device_clock*(ring: pfring, ts: Timespec): cint {.pf.}
proc pfring_set_device_clock*(ring: pfring, ts: Timespec): cint {.pf.}
proc pfring_adjust_device_clock*(ring: pfring, offset: Timespec, sign: int8): cint {.pf.}
proc pfring_sync_indexes_with_kernel*(ring: pfring) {.pf.}
proc pfring_send_last_rx_packet*(ring: pfring, tx_interface_id: cint): cint {.pf.}
proc pfring_get_link_status*(ring: pfring): cint {.pf.}
proc pfring_get_num_tx_slots*(ring: pfring): cint {.pf.}
proc pfring_copy_tx_packet_into_slot*(ring: pfring, tx_slot_id: cushort, buffer: cstring, length: cuint): cint {.pf.}
proc pfring_get_pkt_buff_data*(ring: pfring, pkt_handle: pfring_pkt_buff): cuchar {.pf.}
proc pfring_set_pkt_buff_len*(ring: pfring, pkt_handle: pfring_pkt_buff, length: uint32): cint {.pf.}
proc pfring_set_pkt_buff_ifindex*(ring: pfring, pkt_handle: pfring_pkt_buff, if_index: cint): cint {.pf.}
proc pfring_add_pkt_buff_ifindex*(ring: pfring, pkt_handle: pfring_pkt_buff, if_index: cint): cint {.pf.}
proc pfring_alloc_pkt_buff*(ring: pfring): pfring_pkt_buff {.pf.}
proc pfring_release_pkt_buff*(ring: pfring, pkt_handle: pfring_pkt_buff) {.pf.}
proc pfring_recv_pkt_buff*(ring: pfring, pkt_handle: pfring_pkt_buff, hdr: pfring_pkthdr, wait_for_incoming_packet: uint8): cint {.pf.}
proc pfring_send_pkt_buff*(ring: pfring, pkt_handle: pfring_pkt_buff, flush_packet: uint8): cint {.pf.}
proc pfring_flush_tx_packets*(ring: pfring): cint {.pf.}
proc pfring_search_payload*(ring: pfring, string_to_search: cstring): cint {.pf.}
proc pfring_register_zerocopy_tx_ring*(ring: pfring, tx_ring: pfring): cint {.pf.}
proc pfring_bundle_init*(bundle: pfring_bundle, p: bundle_read_policy) {.pf.}
proc pfring_bundle_add*(bundle: pfring_bundle, ring: pfring): cint {.pf.}
proc pfring_bundle_poll*(bundle: pfring_bundle, wait_duration: cuint): cint {.pf.}
proc pfring_bundle_read*(bundle: pfring_bundle, buffer: ptr[cstring], buffer_len: cuint, hdr: pfring_pkthdr, wait_for_incoming_packet: uint8): cint {.pf.}
proc pfring_bundle_destroy*(bundle: pfring_bundle) {.pf.}
proc pfring_bundle_close*(bundle: pfring_bundle) {.pf.}
proc pfring_parse_pkt*(pkt: cstring, hdr: pfring_pkthdr, level, add_timestamp, add_hash: uint8): cint {.pf.}
proc pfring_set_if_promisc*(device: cstring, set_promisc: cint): cint {.pf.}
proc pfring_format_numbers*(val: cdouble, buf: cstring, buf_len: cuint, add_decimals: uint8): cstring {.pf.}
proc pfring_enable_hw_timestamp*(ring: pfring, device_name: cstring, enable_rx, enable_tx: uint8): cint {.pf.}
proc pfring_get_mtu_size*(ring: pfring): cint {.pf.}
proc pfring_get_card_settings*(ring: pfring, settings: pfring_card_settings): cint {.pf.}
proc pfring_print_parsed_pkt*(buff: cstring, buff_len: cuint, p: cstring, h: pfring_pkthdr): cint {.pf.}
proc pfring_print_pkt*(buff: cstring, buff_len: cuint, p: cstring, length, caplen: cuint): cint {.pf.}
proc pfring_recv_chunk*(ring: pfring, chunk: pointer, chunk_len: cuint, wait_for_incoming_chunk: uint8): cint {.pf.}
proc pfring_set_bound_dev_name*(ring: pfring, custom_dev_name: cstring): cint {.pf.}
proc pfring_read_ixia_hw_timestamp*(buffer: cstring, buffer_len: uint32, ts: Timespec): cint {.pf.}
proc pfring_handle_ixia_hw_timestamp*(buffer: cstring, hdr: pfring_pkthdr) {.pf.}
proc pfring_read_vss_apcon_hw_timestamp*(buffer: cstring, buffer_len: uint32, ts: Timespec): cint {.pf.}
proc pfring_handle_vss_apcon_hw_timestamp*(buffer: cstring, hdr: pfring_pkthdr) {.pf.}
proc pfring_parse_bpf_filter*(filter_buffer: cstring, caplen: cint, filter: bpf_program): cint {.pf.}
proc pfring_parse_bpf_filter*(filter_buffer: cstring, caplen: cint, filter: pfring_bpf_program): cint {.pf.}
proc fring_free_bpf_filter*(filter:  bpf_program): cint {.pf.}
proc fring_free_bpf_filter*(filter:  pfring_bpf_program): cint {.pf.}
proc gmt_to_local*(t: TimeInfo): uint32 {.pf.}
