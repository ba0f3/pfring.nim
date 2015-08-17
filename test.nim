import pfring/types
import pfring/core


var ring = newRing("eth1", 65536, PF_RING_PROMISC)
if ring.isNil:
  quit "pfring_open error"

#ring.setBPFFilter("tcp and port 22")
ring.enable()

var buf = newString(512)
while true:
  ring.readParsedDataTo(addr buf)
  if buf.len > 0:
    echo buf
ring.close()
