package easytcp.model.packet;

public class TCPConnection {
  private ConnectionStatus connectionStatus;
  private InternetAddress host;
  private InternetAddress hostTwo;
  private PacketContainer packetContainer = new PacketContainer();

  public TCPConnection() {
  }

  public TCPConnection(TCPConnection connection) {
    this.connectionStatus = connection.getConnectionStatus();
    this.host = connection.getHost();
    this.hostTwo = connection.getHostTwo();
    this.packetContainer = connection.getPacketContainer();
  }

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

  @Override
  public String toString() {
    return connectionStatus.getDisplayText() + " to " + host.getAddressString() + " packet count =" + packetContainer.getPackets().size();
  }
}
