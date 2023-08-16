package easytcp.model.packet;

import org.apache.logging.log4j.util.Strings;

import java.net.InetAddress;
import java.util.Objects;

public class InternetAddress {
  private String alphanumericalAddress;
  private String hostName;
  private InetAddress pcap4jAddress;

  public InternetAddress(InetAddress pcap4jAddress) {
    this.pcap4jAddress = pcap4jAddress;
    this.alphanumericalAddress = pcap4jAddress.getHostAddress() != null ? pcap4jAddress.toString() : "";
    this.hostName = pcap4jAddress.getHostName();
  }

  public InternetAddress(
    InetAddress alphanumericalAddress,
    String hostName,
    InetAddress addressPcap4j) {
    this.alphanumericalAddress = alphanumericalAddress.getHostAddress() != null ? alphanumericalAddress.toString() : "";
    this.hostName = hostName;
    this.pcap4jAddress = addressPcap4j;
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

  @Override
  public int hashCode() {
    return Objects.hash(this.alphanumericalAddress, this.pcap4jAddress);
  }

  @Override
  public boolean equals(Object obj) {
    // self check
    if (this == obj)
      return true;
    // null check
    if (obj == null)
      return false;
    // type check and cast
    if (getClass() != obj.getClass())
      return false;
    InternetAddress otherAddress = (InternetAddress) obj;
    // field comparison
    return Objects.equals(this.alphanumericalAddress, otherAddress.alphanumericalAddress)
      || Objects.equals(this.pcap4jAddress, otherAddress.pcap4jAddress);
  }
}
