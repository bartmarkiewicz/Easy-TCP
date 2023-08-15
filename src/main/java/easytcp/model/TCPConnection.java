package easytcp.model;

import java.util.ArrayList;
import java.util.List;

public class TCPConnection {
  private ConnectionStatus connectionStatus;
  private InternetAddress host;
  private InternetAddress hostTwo;
  private List<EasyTCPacket> packetList = new ArrayList<>();

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

  public List<EasyTCPacket> getPacketList() {
    return packetList;
  }

  public void setPacketList(List<EasyTCPacket> packetList) {
    this.packetList = packetList;
  }
}
