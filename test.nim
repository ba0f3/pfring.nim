import pfring/types
import pfring/core


var ring = newRing("eth1", 1024, PF_RING_ZC_SYMMETRIC_RSS)
if ring.isNil:
  quit "pfring_open error"

ring.enable()
while true:
  var buf = ring.readPacketData()
  echo buf
  echo ring.header.caplen, " ", ring.header.length, " ", buf.len
ring.close()
