package easytcp.model.packet;

public class TCPConnection {
  private ConnectionStatus connectionStatus;
  private InternetAddress host;
  private InternetAddress hostTwo;
  private PacketContainer packetContainer = new PacketContainer();

  public ConnectionStatus getConnectionStatus() {
    return connectionStatus;
  }

  public void setConnectionStatus(ConnectionStatus connectionStatus) {
    this.connectionStatus = connectionStatus;
  }

  public InternetAddress getHost() {
    return host;
  }

  public void setHost(InternetAddress host) {
    this.host = host;
  }

  public InternetAddress getHostTwo() {
    return hostTwo;
  }

  public void setHostTwo(InternetAddress hostTwo) {
    this.hostTwo = hostTwo;
  }

  public PacketContainer getPacketContainer() {
    return packetContainer;
  }

  public void setPacketContainer(PacketContainer packetContainer) {
    this.packetContainer = packetContainer;
  }
}
