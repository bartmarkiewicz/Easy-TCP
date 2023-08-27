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

  public static TCPConnection getConnectionWithHandshakeAndFin() {
    var con = createTCPConnection(true, createAddress("192", "fish.com"),
      createAddress("333", "host.com"));
    var synSentPacket =
      TestUtils.createEasyTcpDataPacket(con, true, 0L, 1L, 0, List.of(TCPFlag.SYN));
    synSentPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.12345678"));
    var synReceivedPacket =
      TestUtils.createEasyTcpDataPacket(
        con, false, 1L, 2L, 0, List.of(TCPFlag.SYN, TCPFlag.ACK));
    synReceivedPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.22345678"));

    var pshPcktSent =
      TestUtils.createEasyTcpDataPacket(con, true, 2L, 3L, 40, List.of(TCPFlag.PSH, TCPFlag.ACK));
    pshPcktSent.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.32345678"));

    var pshPcktReceived =
      TestUtils.createEasyTcpDataPacket(
        con, false, 43L, 4L, 2, List.of(TCPFlag.PSH, TCPFlag.ACK));
    pshPcktReceived.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.42345678"));


    var finPcktAckSnt =
      TestUtils.createEasyTcpDataPacket(con, true, 5L, 5L, 40, List.of(TCPFlag.FIN, TCPFlag.ACK));
    finPcktAckSnt.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.52345678"));

    var finPcktRcvd =
      TestUtils.createEasyTcpDataPacket(
        con, false, 45L, 5L, 0, List.of(TCPFlag.FIN, TCPFlag.ACK));
    finPcktRcvd.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.62345678"));

    var finalAck =
      TestUtils.createEasyTcpDataPacket(
        con, false, 46L, 5L, 0, List.of(TCPFlag.ACK));
    finalAck.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.82345678"));
    con.getPacketContainer().addPacketToContainer(synReceivedPacket);
    con.getPacketContainer().addPacketToContainer(pshPcktReceived);
    con.getPacketContainer().addPacketToContainer(synSentPacket);
    con.getPacketContainer().addPacketToContainer(pshPcktSent);
    con.getPacketContainer().addPacketToContainer(finPcktRcvd);
    con.getPacketContainer().addPacketToContainer(finPcktAckSnt);
    con.getPacketContainer().addPacketToContainer(finalAck);

    return con;
  }

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
    packet.setWindowSize(50);
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

  public static TCPConnection getConnectionWithHandshakeAndFinCloseWait() {
    var con = createTCPConnection(true, createAddress("192", "fish.com"),
      createAddress("333", "host.com"));
    var synSentPacket =
      TestUtils.createEasyTcpDataPacket(con, true, 0L, 1L, 0, List.of(TCPFlag.SYN));
    synSentPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.12345678"));
    var synReceivedPacket =
      TestUtils.createEasyTcpDataPacket(
        con, false, 1L, 2L, 0, List.of(TCPFlag.SYN, TCPFlag.ACK));
    synReceivedPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.22345678"));

    var pshPcktSent =
      TestUtils.createEasyTcpDataPacket(con, true, 2L, 3L, 40, List.of(TCPFlag.PSH, TCPFlag.ACK));
    pshPcktSent.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.32345678"));

    var pshPcktReceived =
      TestUtils.createEasyTcpDataPacket(
        con, false, 43L, 4L, 2, List.of(TCPFlag.PSH, TCPFlag.ACK));
    pshPcktReceived.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.42345678"));


    var finPcktAckSnt =
      TestUtils.createEasyTcpDataPacket(con, false, 5L, 5L, 40, List.of(TCPFlag.FIN, TCPFlag.ACK));
    finPcktAckSnt.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.52345678"));

    var finPcktRcvd =
      TestUtils.createEasyTcpDataPacket(
        con, true, 45L, 5L, 0, List.of(TCPFlag.FIN, TCPFlag.ACK));
    finPcktRcvd.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.62345678"));

    var finalAck =
      TestUtils.createEasyTcpDataPacket(
        con, false, 46L, 5L, 0, List.of(TCPFlag.ACK));
    finalAck.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.82345678"));
    con.getPacketContainer().addPacketToContainer(synReceivedPacket);
    con.getPacketContainer().addPacketToContainer(pshPcktReceived);
    con.getPacketContainer().addPacketToContainer(synSentPacket);
    con.getPacketContainer().addPacketToContainer(pshPcktSent);
    con.getPacketContainer().addPacketToContainer(finPcktRcvd);
    con.getPacketContainer().addPacketToContainer(finPcktAckSnt);
    con.getPacketContainer().addPacketToContainer(finalAck);

    return con;
  }
}
