package easytcp.model;

import org.pcap4j.core.PcapAddress;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class CaptureData {
  private static CaptureData captureData;
  private long tcpConnectionsEstablished;
  private ConcurrentHashMap<String, String> resolvedHostnames = new ConcurrentHashMap<>();
  private List<EasyTCPacket> packets = new ArrayList<>();
  private HashMap<InternetAddress, TCPConnection> tcpConnectionMap = new HashMap<>();
  private List<PcapAddress> interfaceInternetAddress;
  private CaptureData() {
  }

  public static CaptureData getInstance() {
    if (captureData == null) {
      captureData = new CaptureData();
      return captureData;
    } else {
      return captureData;
    }
  }

  public long getTcpConnectionsEstablished() {
    return tcpConnectionMap.size();
  }

  public void setTcpConnectionsEstablished(long tcpConnectionsEstablished) {
    this.tcpConnectionsEstablished = tcpConnectionsEstablished;
  }

  public ConcurrentHashMap<String, String> getResolvedHostnames() {
    return resolvedHostnames;
  }

  public void setResolvedHostnames(ConcurrentHashMap<String, String> resolvedHostnames) {
    this.resolvedHostnames = resolvedHostnames;
  }

  public List<EasyTCPacket> getPackets() {
    return packets;
  }

  public void setPackets(List<EasyTCPacket> packets) {
    this.packets = packets;
  }

  public static CaptureData getCaptureData() {
    return captureData;
  }

  public static void setCaptureData(CaptureData captureData) {
    CaptureData.captureData = captureData;
  }

  public HashMap<InternetAddress, TCPConnection> getTcpConnectionMap() {
    return tcpConnectionMap;
  }

  public void setTcpConnectionMap(HashMap<InternetAddress, TCPConnection> tcpConnectionMap) {
    this.tcpConnectionMap = tcpConnectionMap;
  }

  public void clear() {
    this.packets.clear();;
    this.tcpConnectionsEstablished = 0L;
    this.tcpConnectionMap.clear();
  }

  public List<PcapAddress> getInterfaceInternetAddress() {
    return interfaceInternetAddress;
  }

  public void setInterfaceInternetAddress(List<PcapAddress> interfaceInternetAddress) {
    this.interfaceInternetAddress = interfaceInternetAddress;
  }
}
