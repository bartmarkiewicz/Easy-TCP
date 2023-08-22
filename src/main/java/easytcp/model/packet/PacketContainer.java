package easytcp.model.packet;

import easytcp.model.TCPFlag;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpOptionKind;

import java.util.*;
import java.util.stream.Collectors;

public class PacketContainer {
  private final List<EasyTCPacket> packets = new ArrayList<>();

  public PacketContainer() {
  }

  public PacketContainer(PacketContainer packetContainer) {
    this.packets.addAll(packetContainer.getPackets());
  }

  public List<EasyTCPacket> findPacketsWithSeqNum(Long seq) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> seq.equals(pkt.getSequenceNumber()))
      .toList();
  }

  public List<EasyTCPacket> findPacketsWithOption(TcpOptionKind tcpOptionKind) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> pkt.getTcpOptions()
        .stream()
        .map(TcpPacket.TcpOption::getKind)
        .toList()
        .contains(tcpOptionKind))
      .toList();
  }

  public List<TcpOptionKind> getUniqueTcpOptions() {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> !pkt.getTcpOptions().isEmpty())
      .flatMap(pkt -> pkt.getTcpOptions().stream().filter(i -> !i.getKind().equals(TcpOptionKind.NO_OPERATION)))
      .map(TcpPacket.TcpOption::getKind)
      .distinct()
      .toList();
  }

  public Optional<EasyTCPacket> findLatestPacketWithSeqNumberLessThan(Long ackNumber) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> ackNumber > pkt.getSequenceNumber())
      .max(Comparator.comparing(EasyTCPacket::getTimestamp));
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

  public Map<Boolean, List<EasyTCPacket>> findPacketsWithFlagOutGoingOrNot(TCPFlag flag) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> pkt.getTcpFlags().get(flag))
      .collect(Collectors.partitioningBy((EasyTCPacket pkt) -> pkt.getOutgoingPacket() == true));
  }

  public List<EasyTCPacket> getPackets() {
    return new ArrayList<>(packets);
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

  public synchronized void clearPackets() {
    this.packets.clear();
  }

  public Long getBytesSentOrReceived(boolean outGoing) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> pkt.getOutgoingPacket() == outGoing)
      .mapToLong(EasyTCPacket::getDataPayloadLength)
      .sum();
  }

  public Optional<EasyTCPacket> findPacketWith(Long seq, Long ack, Integer payloadLen, String tcpFlagsDisplayable) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> seq.equals(pkt.getSequenceNumber())
        && pkt.getAckNumber().equals(ack)
        && pkt.getTcpFlagsDisplayable().equals(tcpFlagsDisplayable)
        && pkt.getDataPayloadLength().equals(payloadLen))
      .findFirst();

  }

  public long getPacketsCountRetransmissions(boolean outgoingPacket) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> outgoingPacket == pkt.getOutgoingPacket())
      .filter(pkt -> findPacketsWithSeqNum(pkt.getSequenceNumber())
        .stream()
        .filter(i -> {
          var payloadIsSame = i.getDataPayloadLength().equals(pkt.getDataPayloadLength());
          if (payloadIsSame) {
            return i.getAckNumber().equals(pkt.getAckNumber());
          } else {
            return false;
          }
        })
        .toList().size() > 1)
      .count();
  }
}
