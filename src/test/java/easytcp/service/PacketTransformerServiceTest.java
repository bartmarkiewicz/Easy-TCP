package easytcp.service;

import easytcp.model.IPprotocol;
import easytcp.model.PcapCaptureData;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.InternetAddress;
import easytcp.model.packet.TCPConnection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;

class PacketTransformerServiceTest {
  private PacketTransformerService underTest;
  private IpV4Packet pcap4jIpPacket;
  private TcpPacket pcap4jTCPacket;
  private InetAddress srcAddr;
  private InetAddress dstAddr;

  @BeforeEach
  void setUp() throws UnknownHostException {
    underTest = new PacketTransformerService();
    dstAddr = InetAddress.getByName("fish.com");
    srcAddr = InetAddress.getByName("google.com");
    pcap4jTCPacket = new TcpPacket.Builder()
      .ack(true)
      .psh(true)
      .acknowledgmentNumber(55)
      .dstAddr(dstAddr)
      .dstPort(TcpPort.HELLO_PORT)
      .srcPort(TcpPort.HELLO_PORT)
      .srcAddr(srcAddr)
      .sequenceNumber(100)
      .window((short) 33)
      .build();

    pcap4jIpPacket = new IpV4Packet.Builder().dstAddr((Inet4Address) dstAddr)
      .srcAddr((Inet4Address) srcAddr)
      .version(IpVersion.IPV4)
      .protocol(IpNumber.ACTIVE_NETWORKS)
      .tos(new IpV4Packet.IpV4Tos() {
        @Override
        public byte value() {
          return 0;
        }
      })
      .build();
  }

  @Test
  void fromPackets() throws UnknownHostException {
    var result = underTest.fromPackets(pcap4jIpPacket, pcap4jTCPacket,
      Timestamp.valueOf("2018-11-12 13:02:56.82345678"), CaptureData.getInstance(), FiltersForm.getInstance());

    assertThat(result)
      .extracting(
        EasyTCPacket::getAckNumber,
        EasyTCPacket::getSequenceNumber,
        EasyTCPacket::getOutgoingPacket,
        EasyTCPacket::getiPprotocol,
        EasyTCPacket::getDataPayloadLength,
        EasyTCPacket::getTcpFlagsDisplayable,
        EasyTCPacket::getHeaderPayloadLength)
      .containsExactly(55L, 100L, false, IPprotocol.IPV4, 0, ".P", 20);

    assertThat(result.getTcpConnection())
      .extracting(TCPConnection::getConnectionStatus,
        TCPConnection::getHost,
        TCPConnection::getHostTwo,
        i -> i.getPacketContainer().getPackets(),
        TCPConnection::getMaximumSegmentSizeClient,
        TCPConnection::getMaximumSegmentSizeServer,
        TCPConnection::getWindowScaleClient,
        TCPConnection::getWindowScaleServer)
      .containsExactly(ConnectionStatus.UNKNOWN,
        new InternetAddress(dstAddr.getHostAddress(), "fish.com", dstAddr, 652),
        new InternetAddress(srcAddr.getHostAddress(), "google.com", srcAddr, 652),
        List.of(result),
        null,
        null,
        null,
        null);
  }

  @Test
  void storePcap4jPackets() {
    var timestamp = Timestamp.from(Instant.now());
    underTest.storePcap4jPackets(pcap4jIpPacket, pcap4jTCPacket, timestamp);

    assertThat(PacketTransformerService.getPcapCaptureData())
      .containsExactly(new PcapCaptureData(pcap4jTCPacket, pcap4jIpPacket, timestamp));
  }

  @Test
  void transformCapturedPackets() {
    var timestamp = Timestamp.from(Instant.now());
    underTest.storePcap4jPackets(pcap4jIpPacket, pcap4jTCPacket, timestamp);

    underTest.transformCapturedPackets();

    var result = CaptureData.getCaptureData();

    assertThat(result.getPackets().getPackets()).hasSize(1);

    assertThat(result.getTcpConnectionsEstablished()).isEqualTo(1);
    assertThat(result.getResolvedHostnames())
      .contains(
        entry(srcAddr.getHostAddress(), "google.com"),
        entry(dstAddr.getHostAddress(), "fish.com"));

    assertThat(result.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.UNKNOWN)))
      .containsExactly(result.getPackets().getPackets().get(0).getTcpConnection());


    assertThat(result.getPackets().getPackets().get(0))
      .extracting(
        EasyTCPacket::getAckNumber,
        EasyTCPacket::getSequenceNumber,
        EasyTCPacket::getOutgoingPacket,
        EasyTCPacket::getiPprotocol,
        EasyTCPacket::getDataPayloadLength,
        EasyTCPacket::getTcpFlagsDisplayable,
        EasyTCPacket::getHeaderPayloadLength)
      .containsExactly(55L, 100L, false, IPprotocol.IPV4, 0, ".P", 20);

    assertThat(result.getTcpConnectionMap().values())
      .extracting(TCPConnection::getConnectionStatus,
        TCPConnection::getHost,
        TCPConnection::getHostTwo,
        i -> i.getPacketContainer().getPackets(),
        TCPConnection::getMaximumSegmentSizeClient,
        TCPConnection::getMaximumSegmentSizeServer,
        TCPConnection::getWindowScaleClient,
        TCPConnection::getWindowScaleServer)
      .containsExactly(tuple(ConnectionStatus.UNKNOWN,
        new InternetAddress(dstAddr.getHostAddress(), "fish.com", dstAddr, 652),
        new InternetAddress(srcAddr.getHostAddress(), "google.com", srcAddr, 652),
        List.of(result.getPackets().getPackets().get(0)),
        null,
        null,
        null,
        null));

  }
}