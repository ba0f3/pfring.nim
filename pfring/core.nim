import sharedstrings

import types
import wrapper

type
  Ring* = ref object
    cptr*: pfring
    caplen*: int
    header*: pfring_pkthdr
    buffer*: SharedString


  Result = int32


const
  Error: Result = -1
  NoPacketCaptured: Result = 0
  Ok: Result = 1
  RingNotEnabled: Result = -12

proc setApplicationName*(r: Ring, name: string) =
  let res = pfring_set_application_name(r.cptr, name)
  if res != 0:
    raise newException(SystemError, "Unable to set ring application name, error code: " & $res)

proc newRing*(device, appname: string, caplen, flags: uint32): Ring =
  new(result)
  result.cptr = pfring_open(device, caplen, flags)
  if result.cptr.isNil:
    raise newException(SystemError, "Unable to open " & device & " for capturing")
  result.caplen = caplen.int
  new(result.header)
  result.buffer = newSharedString(caplen)


  result.setApplicationName(appname)

proc newRing*(device: string, caplen, flags: uint32): Ring =
  newRing(device, "pfring.nim", caplen, flags)

proc close*(r: Ring) =
  pfring_close(r.cptr)

proc readPacketDataTo*(r: Ring, buffer: ptr string) =
  var res = pfring_recv(r.cptr, addr r.buffer, r.buffer.len, r.header, 1)
  if res != Ok:
    return
  buffer[] = $r.buffer[0..r.header.caplen]

proc readPacketData*(r: Ring): string =
  result = ""
  r.readPacketDataTo(addr result)

proc enable*(r: Ring) =
  var res = pfring_enable_ring(r.cptr)
  if res != 0:
    raise newException(SystemError, "Unable to enable ring, error code " & $res)

proc disable*(r: Ring) =
  var res = pfring_disable_ring(r.cptr)
  if res != 0:
    raise newException(SystemError, "Unable to disable ring, error code " & $res)
