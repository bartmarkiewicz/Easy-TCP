package easytcp.model.packet;

import easytcp.model.TCPFlag;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

public class PacketContainer {
  private final List<EasyTCPacket> packets = new ArrayList<>();

  public Optional<EasyTCPacket> findPacketWithAckNumber(Long ackNumber) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> ackNumber.equals(pkt.getAckNumber()))
      .findFirst();
  }

  public Optional<EasyTCPacket> findPacketWithSeqNumber(Long sequenceNumber) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> sequenceNumber.equals(pkt.getSequenceNumber()))
      .findFirst();
  }

  public Optional<EasyTCPacket> findPacketWithAckNumberAndFlag(Long ackNumber, TCPFlag flag) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> ackNumber.equals(pkt.getAckNumber()) && pkt.getTcpFlags().get(flag))
      .findFirst();
  }

  public Optional<EasyTCPacket> findPacketWithSequenceNumberAndFlag(Long seqNumber, TCPFlag flag) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> seqNumber.equals(pkt.getSequenceNumber()) && pkt.getTcpFlags().get(flag))
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

  public List<EasyTCPacket> getOutgoingPackets() {
    return new ArrayList<>(packets)
      .stream()
      .filter(EasyTCPacket::getOutgoingPacket)
      .toList();
  }

  public List<EasyTCPacket> getIncomingPackets() {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> !pkt.getOutgoingPacket())
      .toList();
  }

  public void clearPackets() {
    this.packets.clear();
  }
}
