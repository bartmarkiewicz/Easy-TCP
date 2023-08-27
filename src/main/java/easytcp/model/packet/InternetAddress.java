package easytcp.model.packet;

import org.apache.logging.log4j.util.Strings;
import org.pcap4j.packet.namednumber.TcpPort;

import java.net.InetAddress;
import java.util.Objects;

/*Represents a host internet address, alongside the port its on
 */
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
    return Objects.hash(alphanumericalAddress, port);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    InternetAddress that = (InternetAddress) o;
    return Objects.equals(alphanumericalAddress, that.alphanumericalAddress)
//      && Arrays.equals(pcap4jAddress.getAddress(), that.pcap4jAddress.getAddress())
      && Objects.equals(port, that.port);
  }

  @Override
  public String toString() {
    return "InternetAddress{" +
      "alphanumericalAddress='" + alphanumericalAddress + '\'' +
      ", hostName='" + hostName + '\'' +
      ", pcap4jAddress=" + pcap4jAddress +
      ", port=" + port +
      '}';
  }
}
