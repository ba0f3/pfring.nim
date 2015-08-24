proc c_sprintf(buf, frmt: cstring) {.header: "<stdio.h>", importc: "sprintf",
                                     varargs, noSideEffect.}

proc intoa*(addr4: int32): cstring =
  ## Experimental `intoa` procs, but performance is not good yet
  ## DO NOT USE
  result = newString(15)
  c_sprintf(result, "%d.%d.%d.%d", (addr4 shr 24) and  0xff, (addr4 shr 16) and 0xff, (addr4 shr 8) and 0xff, addr4 and 0xff)

when isMainModule:
  import posix
  import stopwatch

  let addr4: int32 = -1062715391
  var c1, c2, c3: stopwatch.clock
  var ia2: InAddr
  bench(c1):
    for i in 0..1_000_000:
      discard intoa(addr4)
  bench(c2):
    for i in 0..1_000_000:
      var ia: InAddr
      ia.s_addr = htonl(addr4)
      discard inet_ntoa(ia)
  bench(c3):
    for i in 0..1_000_000:
      ia2.s_addr = htonl(addr4)
      discard inet_ntoa(ia2)

  echo "bench 1): ", c1.seconds
  echo "bench 2): ", c2.seconds
  echo "bench 3): ", c3.seconds
