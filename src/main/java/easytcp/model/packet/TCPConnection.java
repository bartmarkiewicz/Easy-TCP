package easytcp.model.packet;

import easytcp.model.application.FiltersForm;

import java.util.Objects;

/*Class representing a TCP connection from the interface host to another host.
 */
public class TCPConnection {
  private ConnectionStatus connectionStatus;
  private InternetAddress host;
  private InternetAddress hostTwo;
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
    this.host = connection.getHost();
    this.hostTwo = connection.getHostTwo();
    this.packetContainer = new PacketContainer(connection.getPacketContainer());
    this.fullConnection = connection.isFullConnection();
    this.maximumSegmentSizeClient = connection.getMaximumSegmentSizeClient();
    this.maximumSegmentSizeServer = connection.getMaximumSegmentSizeServer();
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

  @Override
  public String toString() {
    return connectionStatus.getDisplayText() + " to " +
      (FiltersForm.getFiltersForm().isResolveHostnames() ? host.getAddressString() : host.getAlphanumericalAddress())
      + " pkts =" + packetContainer.getPackets().size()
      + (fullConnection ? " with handshake" : "");
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    TCPConnection that = (TCPConnection) o;
    return connectionStatus == that.connectionStatus
      && Objects.equals(host, that.host)
      && Objects.equals(hostTwo, that.hostTwo);
  }

  @Override
  public int hashCode() {
    return Objects.hash(connectionStatus, host, hostTwo, packetContainer);
  }
}
