package model;

public class CaptureStats {
  private long packetsCaptured;
  private long tcpConnectionsEstablished;

  public long getPacketsCaptured() {
    return packetsCaptured;
  }

  public void setPacketsCaptured(long packetsCaptured) {
    this.packetsCaptured = packetsCaptured;
  }

  public long getTcpConnectionsEstablished() {
    return tcpConnectionsEstablished;
  }

  public void setTcpConnectionsEstablished(long tcpConnectionsEstablished) {
    this.tcpConnectionsEstablished = tcpConnectionsEstablished;
  }
}
