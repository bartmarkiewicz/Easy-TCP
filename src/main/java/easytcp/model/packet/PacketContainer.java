package easytcp.model.packet;

import easytcp.model.TCPFlag;
import easytcp.model.packet.EasyTCPacket;

import java.util.*;

public class PacketContainer {
  private final List<EasyTCPacket> packets = new ArrayList<>();

  public Optional<EasyTCPacket> findPacketWithAckNumber(Long ackNumber) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> ackNumber.equals(pkt.getAckNumber()))
      .findFirst();
  }

  public Optional<EasyTCPacket> findPacketWithAckNumberAndFlag(Long ackNumber, TCPFlag flag) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> ackNumber.equals(pkt.getAckNumber()) && pkt.getTcpFlags().get(flag))
      .findFirst();
  }

  public void addPacketToContainer(EasyTCPacket easyTCPacket) {
    synchronized (packets) {
      packets.add(easyTCPacket);
      packets.sort(Comparator.comparing(pkt -> pkt.getTimestamp().getTime()));
    }
  }

  public EasyTCPacket getLatestPacket() {
    return packets.get(packets.size() - 1);
  }

  public List<EasyTCPacket> getPackets() {
    return packets;
  }

  public void clearPackets() {
    this.packets.clear();
  }
}
