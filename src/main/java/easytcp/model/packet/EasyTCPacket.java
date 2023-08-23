package easytcp.model.packet;

import easytcp.model.IPprotocol;
import easytcp.model.TCPFlag;
import org.pcap4j.packet.TcpPacket;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/*Represents a single TCP packet alongside some IP header information
 */
public class EasyTCPacket {
  private Timestamp timestamp;
  private IPprotocol iPprotocol;
  private InternetAddress sourceAddress;
  private InternetAddress destinationAddress;
  private Long sequenceNumber;
  private Long ackNumber;
  private Integer windowSize;
  private Integer dataPayloadLength;
  private Integer headerPayloadLength;
  private Map<TCPFlag, Boolean> tcpFlags;
  private List<TcpPacket.TcpOption> tcpOptions;
  private TCPConnection tcpConnection;
  private Boolean outgoingPacket;

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

  public Long getSequenceNumber() {
    return sequenceNumber;
  }

  public void setSequenceNumber(Long sequenceNumber) {
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

  public InternetAddress getSourceAddress() {
    return sourceAddress;
  }

  public void setSourceAddress(InternetAddress sourceAddress) {
    this.sourceAddress = sourceAddress;
  }

  public InternetAddress getDestinationAddress() {
    return destinationAddress;
  }

  public void setDestinationAddress(InternetAddress destinationAddress) {
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
      
      """
        .formatted(
        timestamp.toString(),
      iPprotocol.getDisplayName(),
      sourceAddress.getAddressString(),
      destinationAddress.getAddressString(),
      getTcpFlagsDisplayable(),
      getSequenceNumber(),
      getAckNumber(),
      getWindowSize(),
      getTcpOptionsDisplayable(),
      getDataPayloadLength()
    );
  }

  public String getTcpFlagsDisplayable() {
    return tcpFlags.entrySet()
      .stream()
      .filter(Map.Entry::getValue)
      .map(flag -> flag.getKey().getDisplayName())
      .collect(Collectors.joining());
  }

  public String getTcpOptionsDisplayable() {
    return tcpOptions.stream()
      .map(option -> option.getKind().valueAsString())
      .collect(Collectors.joining(", "));
  }

  public TCPConnection getTcpConnection() {
    return tcpConnection;
  }

  public void setTcpConnection(TCPConnection tcpConnection) {
    this.tcpConnection = tcpConnection;
  }

  public Boolean getOutgoingPacket() {
    return outgoingPacket;
  }

  public void setOutgoingPacket(Boolean outgoingPacket) {
    this.outgoingPacket = outgoingPacket;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    EasyTCPacket that = (EasyTCPacket) o;
    return Objects.equals(timestamp, that.timestamp) && iPprotocol == that.iPprotocol && Objects.equals(sourceAddress, that.sourceAddress) && Objects.equals(destinationAddress, that.destinationAddress) && Objects.equals(sequenceNumber, that.sequenceNumber) && Objects.equals(ackNumber, that.ackNumber) && Objects.equals(windowSize, that.windowSize) && Objects.equals(dataPayloadLength, that.dataPayloadLength) && Objects.equals(headerPayloadLength, that.headerPayloadLength) && Objects.equals(tcpFlags, that.tcpFlags) && Objects.equals(tcpOptions, that.tcpOptions) && Objects.equals(tcpConnection, that.tcpConnection) && Objects.equals(outgoingPacket, that.outgoingPacket);
  }

  @Override
  public int hashCode() {
    return Objects.hash(timestamp, iPprotocol, sourceAddress, destinationAddress, sequenceNumber, ackNumber, windowSize, dataPayloadLength, headerPayloadLength, tcpFlags, tcpOptions, tcpConnection, outgoingPacket);
  }
}
