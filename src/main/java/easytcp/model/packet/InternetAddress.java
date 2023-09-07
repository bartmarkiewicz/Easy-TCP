package easytcp.model.packet;

import org.apache.logging.log4j.util.Strings;

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
    //gets hostname if available, else gets the numeric address
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
    return Objects.hash(alphanumericalAddress, port, pcap4jAddress);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    InternetAddress that = (InternetAddress) o;
    return Objects.equals(alphanumericalAddress, that.alphanumericalAddress)
      && Objects.equals(pcap4jAddress.getHostAddress(), that.pcap4jAddress.getHostAddress())
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
