package easytcp.model.packet;

import org.apache.logging.log4j.util.Strings;
import org.pcap4j.packet.namednumber.TcpPort;

import java.net.InetAddress;
import java.util.Objects;

public class InternetAddress {
  private String alphanumericalAddress;
  private String hostName;
  private InetAddress pcap4jAddress;
  private Integer port;

  public InternetAddress(
    String alphanumericalAddress, String hostName, InetAddress addressPcap4j, Integer tcpPort) {
    this.alphanumericalAddress = alphanumericalAddress;
    this.hostName = hostName;
    this.pcap4jAddress = addressPcap4j;
    this.port = tcpPort;
  }

  public InternetAddress(
    InetAddress alphanumericalAddress,
    String hostName,
    InetAddress addressPcap4j,
    TcpPort tcpPort) {
    this.alphanumericalAddress = alphanumericalAddress.getHostAddress() != null ? alphanumericalAddress.toString() : "";
    this.hostName = hostName;
    this.pcap4jAddress = addressPcap4j;
    this.port = tcpPort.valueAsInt();
  }

  public InetAddress getPcap4jAddress() {
    return pcap4jAddress;
  }

  public void setPcap4jAddress(InetAddress pcap4jAddress) {
    this.pcap4jAddress = pcap4jAddress;
  }

  public void setAlphanumericalAddress(String alphanumericalAddress) {
    this.alphanumericalAddress = alphanumericalAddress;
  }

  public void setHostName(String hostName) {
    this.hostName = hostName;
  }

  public String getAddressString() {
    return !Strings.isEmpty(hostName) ? hostName : alphanumericalAddress;
  }

  public String getAlphanumericalAddress() {
    return alphanumericalAddress;
  }

  public String getHostName() {
    return hostName;
  }

  public Integer getPort() {
    return port;
  }

  public void setPort(Integer port) {
    this.port = port;
  }

  @Override
  public int hashCode() {
    return Objects.hash(this.alphanumericalAddress, this.pcap4jAddress);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    InternetAddress otherAddress = (InternetAddress) obj;
    return Objects.equals(this.port, otherAddress.port)
      && (Objects.equals(this.alphanumericalAddress, otherAddress.alphanumericalAddress)
      || Objects.equals(this.pcap4jAddress, otherAddress.pcap4jAddress)
      || Objects.equals(this.hostName, otherAddress.hostName));
  }
}
