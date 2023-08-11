package model;

import org.apache.logging.log4j.util.Strings;

import java.net.InetAddress;

public class InternetAddress {
  private String alphanumericalAddress;
  private String hostName;

  public InternetAddress(InetAddress alphanumericalAddress, String hostName) {
    this.alphanumericalAddress = alphanumericalAddress.getHostAddress() != null ? alphanumericalAddress.toString() : "";
    this.hostName = hostName;
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
}
