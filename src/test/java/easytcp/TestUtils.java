package easytcp;

import easytcp.model.IPprotocol;
import easytcp.model.TCPFlag;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.InternetAddress;
import easytcp.model.packet.TCPConnection;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public class TestUtils {

  public static TCPConnection createTCPConnection(boolean full, InternetAddress hostOne, InternetAddress hostTwo) {
    var connection = new TCPConnection();
    connection.setFullConnection(full);
    connection.setHost(hostOne);
    connection.setHostTwo(hostTwo);
    return connection;
  }

  public static EasyTCPacket createEasyTcpDataPacket(
    TCPConnection connection,
    boolean outgoing, Long ack,
    Long seq, int payloadLen, List<TCPFlag> flagList) {
    var packet = new EasyTCPacket();
    packet.setOutgoingPacket(outgoing);
    packet.setAckNumber(ack);
    packet.setSequenceNumber(seq);
    packet.setTcpFlags(
      Map.ofEntries(
        Map.entry(TCPFlag.URG, flagList.contains(TCPFlag.URG)),
        Map.entry(TCPFlag.PSH,flagList.contains(TCPFlag.PSH)),
        Map.entry(TCPFlag.RST, flagList.contains(TCPFlag.RST)),
        Map.entry(TCPFlag.ACK, flagList.contains(TCPFlag.ACK)),
        Map.entry(TCPFlag.FIN, flagList.contains(TCPFlag.FIN)),
        Map.entry(TCPFlag.SYN, flagList.contains(TCPFlag.SYN))
      ));
    packet.setiPprotocol(IPprotocol.IPV4);
    packet.setDataPayloadLength(payloadLen);
    packet.setTcpConnection(connection);
    if (outgoing) {
      packet.setDestinationAddress(connection.getHost());
      packet.setSourceAddress(connection.getHostTwo());
    } else {
      packet.setSourceAddress(connection.getHost());
      packet.setDestinationAddress(connection.getHostTwo());
    }
    packet.setHeaderPayloadLength(20);
    packet.setTimestamp(Timestamp.from(Instant.now()));
    packet.setTcpOptions(List.of());
    return packet;
  }

  public static InternetAddress createAddress(String numericalAddress, String hostName) {
    var internetAddress =
      new InternetAddress(numericalAddress, hostName, null, 80);
    return internetAddress;
  }
}
