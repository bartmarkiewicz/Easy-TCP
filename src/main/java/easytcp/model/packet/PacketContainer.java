package easytcp.model.packet;

import easytcp.model.TCPFlag;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpOptionKind;

import java.util.*;
import java.util.stream.Collectors;

/*
 * A wrapper around a list of packets providing helper methods and handling concurrency issues.
 */
public class PacketContainer {
  private final List<EasyTCPacket> packets = new ArrayList<>();

  public PacketContainer() {
  }

  public PacketContainer(PacketContainer packetContainer) {
    this.packets.addAll(packetContainer.getPackets());
  }

  public List<EasyTCPacket> findPacketsWithSeqNum(Long seq, boolean outgoing) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> seq.equals(pkt.getSequenceNumber()) && pkt.getOutgoingPacket() == outgoing)
      .toList();
  }

  //Gets the unique options found inside the packet container
  public List<TcpOptionKind> getUniqueTcpOptions(boolean outgoingPacket) {
    var tempArr = outgoingPacket ? new ArrayList<>(getOutgoingPackets()) : new ArrayList<>(getIncomingPackets());

    return tempArr
      .stream()
      .filter(pkt -> !pkt.getTcpOptions().isEmpty())
      .flatMap(pkt -> pkt.getTcpOptions().stream().filter(i -> !i.getKind().equals(TcpOptionKind.NO_OPERATION)))
      .map(TcpPacket.TcpOption::getKind)
      .distinct()
      .toList();
  }

  //Finds a packet with a sequence number less than the given number, on an outgoing or incoming packet.
  public Optional<EasyTCPacket> findLatestPacketWithSeqNumberLessThan(Long ackNumber, boolean outgoing) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> ackNumber > pkt.getSequenceNumber() && pkt.getOutgoingPacket() == outgoing)
      .max(Comparator.comparing(EasyTCPacket::getTimestamp));
  }

  //Finds the previously received packet
  public Optional<EasyTCPacket> findPreviousPacketReceived(EasyTCPacket pkt) {
    return new ArrayList<>(packets)
      .stream()
      .filter(other -> !(pkt.getOutgoingPacket().equals(other.getOutgoingPacket()))
        && other.getTimestamp().before(pkt.getTimestamp()))
      .max(Comparator.comparing(EasyTCPacket::getTimestamp));
  }

  //Adds the packet to the container while ensuring its sorted by timestamp and prevents concurrency issues.
  public void addPacketToContainer(EasyTCPacket easyTCPacket) {
    synchronized (packets) {
      packets.add(easyTCPacket);
      packets.sort(Comparator.comparing(EasyTCPacket::getTimestamp));
    }
  }

  public List<EasyTCPacket> getAllPacketsWithoutFlag(TCPFlag flag, boolean outgoing) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> !pkt.getTcpFlags().get(flag) && outgoing == pkt.getOutgoingPacket())
      .toList();
  }

  public Map<Boolean, List<EasyTCPacket>> findPacketsWithFlagOutGoingOrNot(TCPFlag flag) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> pkt.getTcpFlags().get(flag))
      .collect(Collectors.partitioningBy(EasyTCPacket::getOutgoingPacket));
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

  //Finds a packet matching the arguments provided to the method in the packet container
  public Optional<EasyTCPacket> findPacketWith(Long seq, Long ack, Integer payloadLen, String tcpFlagsDisplayable) {
    return new ArrayList<>(packets)
      .stream()
      .filter(pkt -> seq.equals(pkt.getSequenceNumber())
        && pkt.getAckNumber().equals(ack)
        && pkt.getTcpFlagsDisplayable().equals(tcpFlagsDisplayable)
        && pkt.getDataPayloadLength().equals(payloadLen))
      .findFirst();
  }
}
