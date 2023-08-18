package easytcp.model.application;

import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.InternetAddress;
import easytcp.model.packet.PacketContainer;
import easytcp.model.packet.TCPConnection;

import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class CaptureData {
  private static CaptureData captureData;
  private ConcurrentHashMap<String, String> resolvedHostnames = new ConcurrentHashMap<>();
  private PacketContainer packets = new PacketContainer();
  private HashMap<InternetAddress, TCPConnection> tcpConnectionMap = new HashMap<>();

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
    return tcpConnectionMap.keySet().size();
  }

  public List<TCPConnection> getTcpConnectionsWithStatus(Set<ConnectionStatus> statusSet) {
    return tcpConnectionMap.values()
      .stream()
      .filter(tcpConnection ->
        tcpConnection.getConnectionStatus() != null && statusSet.contains(tcpConnection.getConnectionStatus()))
      .toList();
  }

  public ConcurrentHashMap<String, String> getResolvedHostnames() {
    return resolvedHostnames;
  }

  public void setResolvedHostnames(ConcurrentHashMap<String, String> resolvedHostnames) {
    this.resolvedHostnames = resolvedHostnames;
  }

  public PacketContainer getPackets() {
    return packets;
  }

  public void setPackets(PacketContainer packets) {
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
    this.packets.clearPackets();
    this.tcpConnectionMap.clear();
  }
}
