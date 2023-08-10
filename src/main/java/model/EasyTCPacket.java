package model;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpVersion;

import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class EasyTCPacket {
  private Timestamp timestamp;
  private IPprotocol iPprotocol;
  private InetAddress sourceAddress;
  private InetAddress destinationAddress;
  private Integer sequenceNumber;
  private Long ackNumber;
  private Integer windowSize;
  private Integer dataPayloadLength;
  private Integer headerPayloadLength;
  private Map<TCPFlag, Boolean> tcpFlags;
  private List<TcpPacket.TcpOption> tcpOptions;

  public static EasyTCPacket fromPackets(IpPacket ipPacket, TcpPacket tcpPacket, Timestamp timestamp) {
    var easyTcpPacket = new EasyTCPacket();
    var ipHeader = ipPacket.getHeader();
    if (ipHeader.getVersion().equals(IpVersion.IPV4)) {
      easyTcpPacket.setiPprotocol(IPprotocol.IPV4);
    } else if (ipPacket.getHeader().getVersion().equals(IpVersion.IPV6)) {
      easyTcpPacket.setiPprotocol(IPprotocol.IPV6);
    } else {
      throw new IllegalStateException("Invalid IP packet version");
    }
    var tcpHeader = tcpPacket.getHeader();
    easyTcpPacket.setAckNumber(tcpHeader.getAcknowledgmentNumberAsLong());
    easyTcpPacket.setDestinationAddress(ipHeader.getDstAddr());
    easyTcpPacket.setSourceAddress(ipHeader.getSrcAddr());
    easyTcpPacket.setTimestamp(timestamp);
    easyTcpPacket.setSequenceNumber(tcpHeader.getSequenceNumber());
    easyTcpPacket.setWindowSize(tcpHeader.getWindowAsInt());
    easyTcpPacket.setDataPayloadLength(tcpPacket.getRawData().length);
    easyTcpPacket.setTcpFlags(
      Map.ofEntries(
        Map.entry(TCPFlag.URG, tcpHeader.getUrg()),
        Map.entry(TCPFlag.PSH, tcpHeader.getPsh()),
        Map.entry(TCPFlag.RST, tcpHeader.getRst()),
        Map.entry(TCPFlag.ACK, tcpHeader.getAck()),
        Map.entry(TCPFlag.FIN, tcpHeader.getFin()),
        Map.entry(TCPFlag.SYN, tcpHeader.getSyn())
      ));
    easyTcpPacket.setTcpOptions(tcpHeader.getOptions());
    easyTcpPacket.setHeaderPayloadLength(tcpHeader.length());
    return easyTcpPacket;
  }

  public Timestamp getTimestamp() {
    return timestamp;
  }

  public void setTimestamp(Timestamp timestamp) {
    this.timestamp = timestamp;
  }

  public IPprotocol getiPprotocol() {
    return iPprotocol;
  }

  public void setiPprotocol(IPprotocol iPprotocol) {
    this.iPprotocol = iPprotocol;
  }

  public Integer getSequenceNumber() {
    return sequenceNumber;
  }

  public void setSequenceNumber(Integer sequenceNumber) {
    this.sequenceNumber = sequenceNumber;
  }

  public Long getAckNumber() {
    return ackNumber;
  }

  public void setAckNumber(Long ackNumber) {
    this.ackNumber = ackNumber;
  }

  public Integer getWindowSize() {
    return windowSize;
  }

  public void setWindowSize(Integer windowSize) {
    this.windowSize = windowSize;
  }

  public Integer getDataPayloadLength() {
    return dataPayloadLength;
  }

  public void setDataPayloadLength(Integer dataPayloadLength) {
    this.dataPayloadLength = dataPayloadLength;
  }

  public InetAddress getSourceAddress() {
    return sourceAddress;
  }

  public void setSourceAddress(InetAddress sourceAddress) {
    this.sourceAddress = sourceAddress;
  }

  public InetAddress getDestinationAddress() {
    return destinationAddress;
  }

  public void setDestinationAddress(InetAddress destinationAddress) {
    this.destinationAddress = destinationAddress;
  }

  public Map<TCPFlag, Boolean> getTcpFlags() {
    return tcpFlags;
  }

  public void setTcpFlags(Map<TCPFlag, Boolean> tcpFlags) {
    this.tcpFlags = tcpFlags;
  }

  public Integer getHeaderPayloadLength() {
    return headerPayloadLength;
  }

  public void setHeaderPayloadLength(Integer headerPayloadLength) {
    this.headerPayloadLength = headerPayloadLength;
  }

  public List<TcpPacket.TcpOption> getTcpOptions() {
    return tcpOptions;
  }

  public void setTcpOptions(List<TcpPacket.TcpOption> tcpOptions) {
    this.tcpOptions = tcpOptions;
  }

  @Override
  public String toString() {
    return """
      %s %s %s > %s: Flags [%s], seq %s, ack %s, win %s, options [%s], length %s
      
      """.formatted(
        timestamp.toString(),
      iPprotocol.getDisplayName(),
      sourceAddress.getHostName(), //check if resolve hostnames enabled then resolve or print ip
      destinationAddress.getHostName(),
      getTcpFlagsDisplayable(),
      getSequenceNumber(),
      getAckNumber(),
      getWindowSize(),
      getTcpOptionsDisplayable(),
      getDataPayloadLength()
    );
  }

  private String getTcpFlagsDisplayable() {
    return tcpFlags.entrySet()
      .stream()
      .filter(Map.Entry::getValue)
      .map(flag -> flag.getKey().getDisplayName())
      .collect(Collectors.joining());
  }

  private String getTcpOptionsDisplayable() {
    return tcpOptions.stream()
      .map(option -> option.getKind().valueAsString())
      .collect(Collectors.joining(", "));
  }
}
