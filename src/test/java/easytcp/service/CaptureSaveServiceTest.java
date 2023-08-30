package easytcp.service;

import easytcp.model.IPprotocol;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.InternetAddress;
import easytcp.model.packet.TCPConnection;
import easytcp.service.capture.PcapFileReaderService;
import easytcp.view.ArrowDiagram;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class CaptureSaveServiceTest {
  private CaptureSaveService underTest = new CaptureSaveService();
  @Test
  void saveArrowDiagram() {
    ApplicationStatus.getStatus().setFrameDimension(new Dimension(50, 50));
    var ad = ArrowDiagram.getInstance();
    var fishFile = new File("fish.png");
    assertThat(fishFile.exists()).isFalse();
    ad.setSize(200, 200);
    underTest.saveArrowDiagram("fish");
    assertThat(fishFile.exists()).isTrue();
    fishFile.deleteOnExit();
  }

  @Test
  void saveCapture_thenRead() throws Exception{
    CaptureData.getInstance().clear();
    PacketTransformerService.getPcapCaptureData().clear();
    var fishFile = new File("fish.pcap");
    var packetTransformerService = new PacketTransformerService();

    var dstAddr = InetAddress.getByName("fish.com");
    var srcAddr = InetAddress.getByName("google.com");
    var pcap4jTCPacket = new TcpPacket.Builder()
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

    var pcap4jIpPacket = new IpV4Packet.Builder().dstAddr((Inet4Address) dstAddr)
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


    packetTransformerService.storePcap4jPackets(
      pcap4jIpPacket, pcap4jTCPacket, Timestamp.valueOf("2018-11-12 13:02:56.82345678"));
    assertThat(fishFile.exists()).isFalse();
    underTest.saveCapture("fish");
    assertThat(fishFile.exists()).isTrue();

    var packetReader = new PcapFileReaderService(packetTransformerService);

    var captureData = packetReader.readPacketFile(fishFile, FiltersForm.getInstance(), new JTextPane(), mock());
    Thread.sleep(500);

    while(ApplicationStatus.getStatus().isLoading().get()) {
      Thread.sleep(500);
    }

    assertThat(captureData.getPackets().getPackets()).hasSize(1);
    assertThat(captureData.getPackets().getPackets().get(0))
      .extracting(
        EasyTCPacket::getAckNumber,
        EasyTCPacket::getSequenceNumber,
        EasyTCPacket::getOutgoingPacket,
        EasyTCPacket::getiPprotocol,
        EasyTCPacket::getDataPayloadLength,
        EasyTCPacket::getTcpFlagsDisplayable,
        EasyTCPacket::getHeaderPayloadLength)
      .containsExactly(55L, 100L, false, IPprotocol.IPV4, 0, ".P", 20);

    assertThat(captureData.getPackets().getPackets().get(0).getTcpConnection())
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
        List.of(captureData.getPackets().getPackets().get(0)),
        null,
        null,
        null,
        null);

    fishFile.deleteOnExit();
  }
}