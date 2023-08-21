package easytcp.model.packet;

import java.util.Objects;

public class TCPConnection {
  private ConnectionStatus connectionStatus;
  private InternetAddress host;
  private InternetAddress hostTwo;
  private PacketContainer packetContainer = new PacketContainer();
  private boolean fullConnection;
  public TCPConnection() {
  }

  public TCPConnection(TCPConnection connection) {
    this.connectionStatus = connection.getConnectionStatus();
    this.host = connection.getHost();
    this.hostTwo = connection.getHostTwo();
    this.packetContainer = new PacketContainer(connection.getPacketContainer());
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

  public boolean isFullConnection() {
    return fullConnection;
  }

  public void setFullConnection(boolean fullConnection) {
    this.fullConnection = fullConnection;
  }

  @Override
  public String toString() {
    return connectionStatus.getDisplayText() + " to " + host.getAddressString()
      + " packet count =" + packetContainer.getPackets().size()
      + (fullConnection ? " with TCP three-way handshake" : "");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    TCPConnection that = (TCPConnection) o;
    return connectionStatus == that.connectionStatus
      && Objects.equals(host, that.host)
      && Objects.equals(hostTwo, that.hostTwo)
      && Objects.equals(packetContainer, that.packetContainer);
  }

  @Override
  public int hashCode() {
    return Objects.hash(connectionStatus, host, hostTwo, packetContainer);
  }
}
