package easytcp.model.application;

import easytcp.model.packet.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;


/*Singleton class to store the capture data
 */
public class CaptureData {
  private static CaptureData captureData;
  private final ConcurrentHashMap<String, String> resolvedHostnames = new ConcurrentHashMap<>();
  private final PacketContainer packets = new PacketContainer();
  private final ConcurrentHashMap<ConnectionAddresses, TCPConnection> tcpConnectionMap = new ConcurrentHashMap<>();

  private CaptureData() {
  }

  public static synchronized CaptureData getInstance() {
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
    return new ArrayList<>(tcpConnectionMap.values())
      .stream()
      .filter(tcpConnection ->
        tcpConnection.getConnectionStatus() != null && statusSet.contains(tcpConnection.getConnectionStatus()))
      .toList();
  }

  public ConcurrentMap<String, String> getResolvedHostnames() {
    return resolvedHostnames;
  }

  public PacketContainer getPackets() {
    return packets;
  }

  public static CaptureData getCaptureData() {
    return captureData;
  }

  public ConcurrentMap<ConnectionAddresses, TCPConnection> getTcpConnectionMap() {
    return tcpConnectionMap;
  }

  public void clear() {
    // notably does not clear the resolved hostnames map
    this.packets.clearPackets();
    this.tcpConnectionMap.clear();
  }
}
