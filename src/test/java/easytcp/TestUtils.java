package easytcp;

import easytcp.model.IPprotocol;
import easytcp.model.TCPFlag;
import easytcp.model.packet.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpWindowScaleOption;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;

/* Test helper util class
 */
public class TestUtils {

  public static TCPConnection getConnectionWithHandshakeAndFin() {
    var con = createTCPConnection(true, createAddress("192", "fish.com"),
      createAddress("333", "host.com"));
    var synSentPacket =
      TestUtils.createEasyTcpDataPacket(con, true, 0L, 1L, 0, List.of(TCPFlag.SYN));
    synSentPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.12345678"));
    synSentPacket.setTcpOptions(List.of(
      new TcpMaximumSegmentSizeOption.Builder().maxSegSize((short) 100).build()));

    var synReceivedPacket =
      TestUtils.createEasyTcpDataPacket(
        con, false, 1L, 2L, 0, List.of(TCPFlag.SYN, TCPFlag.ACK));
    synReceivedPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.23345678"));
    synReceivedPacket.setTcpOptions(List.of(
      new TcpMaximumSegmentSizeOption.Builder().maxSegSize((short) 50).build()));
    var pshPcktSent =
      TestUtils.createEasyTcpDataPacket(con, true, 2L, 3L, 40, List.of(TCPFlag.PSH, TCPFlag.ACK));
    pshPcktSent.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.34345678"));

    var pshPcktReceived =
      TestUtils.createEasyTcpDataPacket(
        con, false, 43L, 4L, 2, List.of(TCPFlag.PSH, TCPFlag.ACK));
    pshPcktReceived.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.43345678"));


    var finPcktAckSnt =
      TestUtils.createEasyTcpDataPacket(con, true, 5L, 5L, 40, List.of(TCPFlag.FIN, TCPFlag.ACK));
    finPcktAckSnt.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.54345678"));

    var finPcktRcvd =
      TestUtils.createEasyTcpDataPacket(
        con, false, 45L, 5L, 0, List.of(TCPFlag.FIN, TCPFlag.ACK));
    finPcktRcvd.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.63345678"));

    var finalAck =
      TestUtils.createEasyTcpDataPacket(
        con, false, 46L, 5L, 0, List.of(TCPFlag.ACK));
    finalAck.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.83345678"));
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
    connection.setConnectionAddresses(new ConnectionAddresses(hostOne, hostTwo));
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
      packet.setDestinationAddress(connection.getConnectionAddresses().addressOne());
      packet.setSourceAddress(connection.getConnectionAddresses().addressTwo());
    } else {
      packet.setSourceAddress(connection.getConnectionAddresses().addressOne());
      packet.setDestinationAddress(connection.getConnectionAddresses().addressTwo());
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

  public static TCPConnection getConnectionWithNagle() {
    var con = createTCPConnection(true, createAddress("192", "fish.com"),
      createAddress("333", "host.com"));
    var synSentPacket =
      TestUtils.createEasyTcpDataPacket(con, true, 0L, 1L, 20, List.of(TCPFlag.SYN));
    synSentPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.12345678"));
    synSentPacket.setTcpOptions(List.of(
      new TcpMaximumSegmentSizeOption.Builder().maxSegSize((short) 20).build(),
      new TcpWindowScaleOption.Builder().length((byte) 1).build()));
    con.setMaximumSegmentSizeClient((long) 20);
    con.setWindowScaleClient(2);

    var synReceivedPacket =
      TestUtils.createEasyTcpDataPacket(
        con, false, 21L, 1L, 20, List.of(TCPFlag.SYN, TCPFlag.ACK));
    synReceivedPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.13345678"));
    synReceivedPacket.setTcpOptions(List.of(
      new TcpMaximumSegmentSizeOption.Builder().maxSegSize((short) 20).build(),
      new TcpWindowScaleOption.Builder().length((byte) 20).build()));
    con.setMaximumSegmentSizeServer((long) 20);
    con.setWindowScaleServer(1);
    var pshPcktSent =
      TestUtils.createEasyTcpDataPacket(con, true, 21L, 21L, 20, List.of(TCPFlag.ACK));
    pshPcktSent.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.14345678"));

    var pshPcktReceived =
      TestUtils.createEasyTcpDataPacket(
        con, false, 41L, 41L, 20, List.of(TCPFlag.ACK));
    pshPcktReceived.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.15345678"));


    var dataPcktAckSnt =
      TestUtils.createEasyTcpDataPacket(con, true, 61L, 41L, 20, List.of(TCPFlag.ACK));
    dataPcktAckSnt.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.17345678"));

    var dataPcktRcvd =
      TestUtils.createEasyTcpDataPacket(
        con, false, 61L, 61L, 20, List.of(TCPFlag.ACK));
    dataPcktRcvd.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.18345678"));

    var finalAck =
      TestUtils.createEasyTcpDataPacket(
        con, true, 81L, 81L, 20, List.of(TCPFlag.ACK));
    finalAck.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.19345678"));
    con.getPacketContainer().addPacketToContainer(synReceivedPacket);
    con.getPacketContainer().addPacketToContainer(pshPcktReceived);
    con.getPacketContainer().addPacketToContainer(synSentPacket);
    con.getPacketContainer().addPacketToContainer(pshPcktSent);
    con.getPacketContainer().addPacketToContainer(dataPcktRcvd);
    con.getPacketContainer().addPacketToContainer(dataPcktAckSnt);
    con.getPacketContainer().addPacketToContainer(finalAck);

    return con;
  }

  public static TCPConnection getConnectionWithSlowStart() {
    var con = createTCPConnection(true, createAddress("192", "fish.com"),
      createAddress("333", "host.com"));
    var synSentPacket =
      TestUtils.createEasyTcpDataPacket(con, true, 0L, 1L, 0, List.of(TCPFlag.SYN));
    synSentPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.12345678"));
    synSentPacket.setTcpOptions(List.of(
      new TcpMaximumSegmentSizeOption.Builder().maxSegSize((short) 100).build(),
      new TcpWindowScaleOption.Builder().length((byte) 2).build()));
    con.setMaximumSegmentSizeClient((long) 100);
    con.setWindowScaleClient(2);

    var synReceivedPacket =
      TestUtils.createEasyTcpDataPacket(
        con, false, 1L, 1L, 20, List.of(TCPFlag.SYN, TCPFlag.ACK));
    synReceivedPacket.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.13345678"));
    synReceivedPacket.setTcpOptions(List.of(
      new TcpMaximumSegmentSizeOption.Builder().maxSegSize((short) 100).build(),
      new TcpWindowScaleOption.Builder().length((byte) 2).build()));
    con.setMaximumSegmentSizeServer((long) 100);
    con.setWindowScaleServer(2);
    var pshPcktSent =
      TestUtils.createEasyTcpDataPacket(con, true, 21L, 21L, 20, List.of(TCPFlag.ACK));
    pshPcktSent.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.14145678"));

    var pshPcktReceived =
      TestUtils.createEasyTcpDataPacket(
        con, true, 21L, 41L, 20, List.of(TCPFlag.ACK));
    pshPcktReceived.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.15345678"));

    var dataPcktAckSnt =
      TestUtils.createEasyTcpDataPacket(con, false, 61L, 41L, 20, List.of(TCPFlag.ACK));
    dataPcktAckSnt.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.15555678"));

    var dataPcktRcvd =
      TestUtils.createEasyTcpDataPacket(
        con, true, 61L, 61L, 20, List.of(TCPFlag.ACK));
    dataPcktRcvd.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.17145678"));

    var finalAck =
      TestUtils.createEasyTcpDataPacket(
        con, true, 61L, 81L, 20, List.of(TCPFlag.ACK));
    finalAck.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.18145678"));

    var dataPcktAck2 =
      TestUtils.createEasyTcpDataPacket(con, false, 81L, 61L, 20, List.of(TCPFlag.ACK));
    dataPcktAck2.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.18045678"));

    var dataPcktSnt1 =
      TestUtils.createEasyTcpDataPacket(
        con, true, 81L, 61L, 20, List.of(TCPFlag.ACK));
    dataPcktRcvd.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.19345678"));

    var dataPcktSnt12 =
      TestUtils.createEasyTcpDataPacket(
        con, true, 81L, 81L, 20, List.of(TCPFlag.ACK));
    dataPcktSnt12.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.21345678"));


    var dataPcktSnt3 =
      TestUtils.createEasyTcpDataPacket(
        con, true, 61L, 101L, 20, List.of(TCPFlag.ACK));
    dataPcktSnt3.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.22345678"));

    var dataPcktSnt4 =
      TestUtils.createEasyTcpDataPacket(
        con, true, 61L, 121L, 20, List.of(TCPFlag.ACK));
    dataPcktSnt4.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.23345678"));

    con.getPacketContainer().addPacketToContainer(synReceivedPacket);
    con.getPacketContainer().addPacketToContainer(pshPcktReceived);
    con.getPacketContainer().addPacketToContainer(synSentPacket);
    con.getPacketContainer().addPacketToContainer(pshPcktSent);
    con.getPacketContainer().addPacketToContainer(dataPcktRcvd);
    con.getPacketContainer().addPacketToContainer(dataPcktAckSnt);
    con.getPacketContainer().addPacketToContainer(finalAck);
    con.getPacketContainer().addPacketToContainer(dataPcktSnt4);
    con.getPacketContainer().addPacketToContainer(dataPcktSnt3);
    con.getPacketContainer().addPacketToContainer(dataPcktSnt12);
    con.getPacketContainer().addPacketToContainer(dataPcktSnt1);
    con.setConnectionStatus(ConnectionStatus.UNKNOWN);
    return con;
  }

  public static IpV4Packet createPcap4Packet(TcpPacket.Builder payload) throws Exception{
    var dstAddr = InetAddress.getByName("fish.com");
    var srcAddr = InetAddress.getByName("google.com");

    var pcap4jIpPacket = new IpV4Packet.Builder().dstAddr((Inet4Address) dstAddr)
      .srcAddr((Inet4Address) srcAddr)
      .version(IpVersion.IPV4)
      .protocol(IpNumber.ACTIVE_NETWORKS)
      .tos((IpV4Packet.IpV4Tos) () -> (byte) 0)
      .payloadBuilder(payload)
      .build();
    return pcap4jIpPacket;
  }

  public static TcpPacket.Builder createPcap4jTcpPacketBuilder() throws Exception {
    var dstAddr = InetAddress.getByName("fish.com");
    var srcAddr = InetAddress.getByName("google.com");

    var pcap4jTCPacketBuilder = new TcpPacket.Builder()
      .ack(true)
      .psh(true)
      .acknowledgmentNumber(55)
      .dstAddr(dstAddr)
      .dstPort(TcpPort.HELLO_PORT)
      .srcPort(TcpPort.HELLO_PORT)
      .srcAddr(srcAddr)
      .sequenceNumber(100)
      .window((short) 33);

    return pcap4jTCPacketBuilder;
  }
}
