import wrapper
export wrapper

type
  Ring* = ref object
    cptr*: ptr pfring
    caplen*: int
    header*: pfring_pkthdr
    buffer*: cstring

  Stats* = object
    received*: uint64
    dropped*: uint64

  Direction = packet_direction
  SocketMode = socket_mode
  ClusterType = cluster_type

  Result = int32


const
  ReceiveAndTransmit*: Direction = rx_and_tx_direction
  ReceiveOnly*: Direction = rx_only_direction
  TransmitOnly*: Direction = tx_only_direction

  WriteAndRead*: SocketMode = send_and_recv_mode
  ReadOnly*: SocketMode = recv_only_mode
  WriteOnly*: SocketMode = send_only_mode

  ClusterPerFlow*: ClusterType = cluster_per_flow
  ClusterRoundRobin*: ClusterType = cluster_round_robin
  ClusterPerFlow2Tuple*: ClusterType = cluster_per_flow_2_tuple
  ClusterPerFlow4Tuple*: ClusterType = cluster_per_flow_4_tuple
  ClusterPerFlow5Tuple*: ClusterType = cluster_per_flow_5_tuple
  ClusterPerFlowTCP5Tuple*: ClusterType = cluster_per_flow_tcp_5_tuple

proc setApplicationName*(r: Ring, name: cstring) =
  let res = pfring_set_application_name(r.cptr, name)
  if res != 0:
    raise newException(SystemError, "Unable to set ring application name, error code: " & $res)

proc newRing*(device, appname: string, caplen, flags: uint32): Ring =
  new(result)
  result.cptr = pfring_open(device, caplen, flags)
  if result.cptr.isNil:
    raise newException(SystemError, "Unable to open " & device & " for capturing")
  result.caplen = caplen.int
  result.setApplicationName(appname)

proc newRing*(device: string, caplen, flags: uint32): Ring =
  newRing(device, "pfring.nim", caplen, flags)

proc close*(r: Ring) =
  pfring_close(r.cptr)

proc readPacketData*(r: Ring) =
  let res = pfring_recv(r.cptr, addr r.buffer, r.buffer.len.uint, addr r.header, 1)
  if res != 1 and res != 0:
    raise newException(SystemError, "Unable to read data, error code: " & $res)

proc readPacketDataTo*(r: Ring, buffer: ptr string) =
  r.readPacketData()
  buffer[] = ($r.buffer)[0..r.header.caplen.int]

proc readParsedPacketData*(r: Ring) =
  let res = pfring_recv_parsed(r.cptr, addr r.buffer, r.buffer.len.uint, addr r.header, 1, 4, 1, 1)
  if res < 0:
    raise newException(SystemError, "Unable to read data, error code: " & $res)

proc readParsedPacketDataTo*(r: Ring, buffer: ptr string) =
  r.readParsedPacketData()
  buffer[] = ($r.buffer)[0..r.header.caplen.int]

proc writePacketData*(r: Ring, data: string) =
  let res = pfring_send(r.cptr, data.cstring, data.len.cuint, 1)
  if res < 0:
    raise newException(SystemError, "Unable to send packet data, error code: " & $res)

proc getStats*(r: Ring): Stats =
  var stat: pfring_stat

  let res = pfring_stats(r.cptr, addr stat)
  if res != 0:
    raise newException(SystemError, "Unable to get ring stats, error code: " & $res)

  result.received = stat.recv
  result.dropped = stat.drop

proc printParsedPacket*(r: Ring) =
  var buffer = newString(512)

  discard pfring_print_parsed_pkt(buffer, buffer.len.uint, addr r.buffer, addr r.header)
  #discard pfring_parse_pkt(buffer, r.header, 4, 1, 1)
  echo buffer

proc enable*(r: Ring) =
  let res = pfring_enable_ring(r.cptr)
  if res != 0:
    raise newException(SystemError, "Unable to enable ring, error code " & $res)

proc disable*(r: Ring) =
  let res = pfring_disable_ring(r.cptr)
  if res != 0:
    raise newException(SystemError, "Unable to disable ring, error code " & $res)

proc setBPFFilter*(r: Ring, filter: string) =
  let res = pfring_set_bpf_filter(r.cptr, filter)
  if res != 0:
    raise newException(SystemError, "Unable to set BPF filter, error code: " & $res)

proc removeBPFFilter*(r: Ring) =
  let res = pfring_remove_bpf_filter(r.cptr)
  if res != 0:
    raise newException(SystemError, "Unable to remove BPF filter, error code: " & $res)

proc setDirection*(r: Ring, d: Direction) =
  let res = pfring_set_direction(r.cptr, d)
  if res < 0:
    raise newException(SystemError, "Unable to set ring direction, error code: " & $res)

proc setCluster*(r: Ring, cluster: int, typ: ClusterType) =
  let res = pfring_set_cluster(r.cptr, cluster.cuint, typ)
  if res != 0:
    raise newException(SystemError, "Unable to set cluster, error code: " & $res)

proc removeFromCluster*(r: Ring) =
  let res = pfring_remove_from_cluster(r.cptr)
  if res != 0:
    raise newException(SystemError, "Unable to remove from cluster, error code: " & $res)

proc setSamplingRate*(r: Ring, rate: int) =
  let res = pfring_set_sampling_rate(r.cptr, rate.cuint)
  if res != 0:
    raise newException(SystemError, "Unable to set sampling rate, error code: " & $res)

proc setSocketMode*(r: Ring, s: SocketMode) =
  let res = pfring_set_socket_mode(r.cptr, s)
  if res < 0:
    raise newException(SystemError, "Unable to set socket mode, error code: " & $res)

proc startLoop*(r: Ring, looper: proc (h: ptr pfring_pkthdr, p: ptr cstring, user_bytes: ptr cstring), user_bytes: ptr cstring, wfp: uint8) {.inline.} =
  let res = pfring_loop(r.cptr, looper, user_bytes, wfp)
  if res < 0:
    raise newException(SystemError, "Unable to set looper callback, error code: " & $res)

proc breakLoop*(r: Ring) =
  pfring_breakloop(r.cptr)

proc parsePacket*(p: ptr cstring, h: ptr pfring_pkthdr, level, timestamp, hash: uint8) =
  let res = pfring_parse_pkt(p, h, level, timestamp, hash)
  if res < 0:
    raise newException(SystemError, "Unable to parse packet, error code: " & $res)
