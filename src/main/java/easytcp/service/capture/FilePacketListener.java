package easytcp.service.capture;

import easytcp.service.PacketTransformerService;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

/*This is the listener which gets called for each packet captured or read from a file
 */
public class FilePacketListener implements PacketListener {
  private final PacketTransformerService packetTransformerService;
  private final PcapHandle pcapHandle;

  public FilePacketListener(PacketTransformerService packetTransformerService, PcapHandle pcapHandle) {
    this.packetTransformerService = packetTransformerService;
    this.pcapHandle = pcapHandle;
  }

  @Override
  public void gotPacket(Packet packet) {
    //extracts the IP and TCP packets from the raw packet
    var ipPacket = packet.get(IpPacket.class);
    if (ipPacket != null) {
      var tcpPacket = ipPacket.get(TcpPacket.class);
      if (tcpPacket != null) {
        //stores each packet to be transformed later
        packetTransformerService.storePcap4jPackets(ipPacket, tcpPacket, pcapHandle.getTimestamp());
      }
    }
  }
}
