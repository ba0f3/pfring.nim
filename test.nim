import pfring/core

var ring = newRing("eth1", 65536, PF_RING_PROMISC)
if ring.isNil:
  quit "pfring_open error"

proc signalHandler() {.noconv.} =
  var stat = ring.getStats()
  echo "Received " & $stat.received & " packets, dropped " & $stat.dropped & " packets"
  ring.close()

setControlCHook(signalHandler)


ring.setBPFFilter("tcp and port 80")
ring.enable()
ring.setDirection(ReceiveOnly)
#ring.setSocketMode(ReadOnly)
var buf = newString(512)
while true:
  ring.readParsedPacketDataTo(addr buf)
  #ring.printParsedPacket()
  var flags = ring.header.extended_pkthdr.parsed_pkt.tcp.flags
  var syn =  (flags and TH_SYN) != 0
  var ack =  (flags and TH_ACK) != 0
  if syn and not ack:
    echo "SYN"
  elif syn and ack:
    echo "SYN-ACK"
  elif ack and not syn:
    echo "ACK"
  else:
    echo "UKN"
