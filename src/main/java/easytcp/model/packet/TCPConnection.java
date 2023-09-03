package easytcp.model.packet;

import easytcp.model.application.FiltersForm;

import java.util.Objects;

/*Class representing a TCP connection from the interface host to another host.
 */
public class TCPConnection {
  private ConnectionStatus connectionStatus;
  private ConnectionStatus statusAsOfPacketTraversal; //keeps track of current status when looping through packets on the connection
  private ConnectionAddresses connectionAddresses;
  private PacketContainer packetContainer = new PacketContainer();
  private Long maximumSegmentSizeClient;
  private Long maximumSegmentSizeServer;
  private Integer windowScaleClient;
  private Integer windowScaleServer;
  private boolean fullConnection; // indicates weather a TCP handshake was captured

  public TCPConnection() {
  }

  public TCPConnection(TCPConnection connection) {
    this.connectionStatus = connection.getConnectionStatus();
    this.connectionAddresses = new ConnectionAddresses(connection.getConnectionAddresses());
    this.packetContainer = new PacketContainer(connection.getPacketContainer());
    this.fullConnection = connection.isFullConnection();
    this.maximumSegmentSizeClient = connection.getMaximumSegmentSizeClient();
    this.maximumSegmentSizeServer = connection.getMaximumSegmentSizeServer();
    this.windowScaleClient = connection.getWindowScaleClient();
    this.windowScaleServer = connection.getWindowScaleServer();
  }

  public ConnectionStatus getConnectionStatus() {
    return connectionStatus;
  }

  public void setConnectionStatus(ConnectionStatus connectionStatus) {
    this.connectionStatus = connectionStatus;
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

  public Long getMaximumSegmentSizeClient() {
    return maximumSegmentSizeClient;
  }

  public void setMaximumSegmentSizeClient(Long maximumSegmentSizeClient) {
    this.maximumSegmentSizeClient = maximumSegmentSizeClient;
  }

  public Long getMaximumSegmentSizeServer() {
    return maximumSegmentSizeServer;
  }

  public void setMaximumSegmentSizeServer(Long maximumSegmentSizeServer) {
    this.maximumSegmentSizeServer = maximumSegmentSizeServer;
  }

  public Integer getWindowScaleClient() {
    return windowScaleClient;
  }

  public void setWindowScaleClient(Integer windowScaleClient) {
    this.windowScaleClient = windowScaleClient;
  }

  public Integer getWindowScaleServer() {
    return windowScaleServer;
  }

  public void setWindowScaleServer(Integer windowScaleServer) {
    this.windowScaleServer = windowScaleServer;
  }

  public ConnectionStatus getStatusAsOfPacketTraversal() {
    return statusAsOfPacketTraversal;
  }

  public void setStatusAsOfPacketTraversal(ConnectionStatus statusAsOfPacketTraversal) {
    this.statusAsOfPacketTraversal = statusAsOfPacketTraversal;
  }

  public ConnectionAddresses getConnectionAddresses() {
    return connectionAddresses;
  }

  public void setConnectionAddresses(ConnectionAddresses connectionAddresses) {
    this.connectionAddresses = connectionAddresses;
  }

  @Override
  public String toString() {
    return "From port %s to ".formatted(connectionAddresses.getAddressTwo().getPort()) +
      (FiltersForm.getInstance().isResolveHostnames()
              ? connectionAddresses.getAddressOne().getAddressString()
              : connectionAddresses.getAddressOne().getAlphanumericalAddress())
      + ":%s pkts =".formatted(connectionAddresses.getAddressOne().getPort()) + packetContainer.getPackets().size()
      + (fullConnection ? " with handshake" : "");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    TCPConnection that = (TCPConnection) o;
    return connectionStatus == that.connectionStatus
      && Objects.equals(connectionAddresses, that.connectionAddresses);
  }

  @Override
  public int hashCode() {
    return Objects.hash(connectionStatus, connectionAddresses);
  }
}
