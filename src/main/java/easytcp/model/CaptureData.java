package easytcp.model;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

public class CaptureData {
  private long tcpConnectionsEstablished;
  private ConcurrentHashMap<String, String> resolvedHostnames = new ConcurrentHashMap<>();
  private List<EasyTCPacket> packets = new ArrayList<>();

  public long getTcpConnectionsEstablished() {
    return tcpConnectionsEstablished;
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

  public void clear() {
    this.packets.clear();;
    this.tcpConnectionsEstablished = 0L;
  }
}
