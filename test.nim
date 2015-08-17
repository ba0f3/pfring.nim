import pfring/types
import pfring/core
import pfring/wrapper

var ring = newRing("eth1", 65536, PF_RING_PROMISC)
if ring.isNil:
  quit "pfring_open error"

#ring.setBPFFilter("tcp and port 22")
ring.enable()

var buf = newString(512)
while true:
  ring.readParsedPacketDataTo(addr buf)
  ring.printParsedPacket()

  discard pfring_parse_pkt(buf, ring.header, 4, 1, 1)

  echo ring.header.extended_pkthdr.parsed_header_len
  #echo ring.header.extended_pkthdr.parsed_header_len
ring.close()
