package easytcp.service;

import easytcp.TestUtils;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;

class PacketDisplayServiceTest {
  private final PacketDisplayService underTest = new PacketDisplayService();
  private TCPConnection connection;
  private EasyTCPacket synSentPkt;
  private EasyTCPacket synReceivedPkt;
  private EasyTCPacket pshReceivedPkt;
  private EasyTCPacket pshSentPkt;
  @BeforeEach
  void setUp() {
    connection = TestUtils.getConnectionWithHandshakeAndFin();
    synSentPkt = connection.getPacketContainer().getPackets().get(0);
    synReceivedPkt = connection.getPacketContainer().getPackets().get(1);
    pshSentPkt = connection.getPacketContainer().getPackets().get(2);
    pshReceivedPkt = connection.getPacketContainer().getPackets().get(3);

    FiltersForm.getInstance().restoreDefaults();
  }

  @Test
  void isVisible_defaultFilters() {
    var defaultFilters = FiltersForm.getInstance();
    var resultPsh = underTest.isVisible(pshSentPkt, defaultFilters);
    var resultSyn = underTest.isVisible(synSentPkt, defaultFilters);
    assertThat(resultPsh).isTrue();
    assertThat(resultSyn).isTrue();
  }

  @Test
  void isVisible_selectedConnection() {
    var filtersForm = FiltersForm.getInstance();

    var newCon = TestUtils.createTCPConnection(
      true,
      TestUtils.createAddress("12333", "differentHostname"),
      TestUtils.createAddress("12335553", "differentHostname2"));

    filtersForm.setSelectedConnection(newCon);
    pshSentPkt.setSourceAddress(newCon.getConnectionAddresses().getAddressOne());
    pshSentPkt.setTcpConnection(newCon);
    var resultPsh = underTest.isVisible(pshSentPkt, filtersForm);
    var resultSyn = underTest.isVisible(synSentPkt, filtersForm);
    assertThat(resultPsh).isTrue();
    assertThat(resultSyn).isFalse();
  }

  @Test
  void isVisible_hostPartialMatch() {
    var filtersForm = FiltersForm.getInstance();

    var newCon = TestUtils.createTCPConnection(
      true,
      TestUtils.createAddress("12333", "differentHostname"),
      TestUtils.createAddress("12335553", "differentHostname2"));

    filtersForm.setHostSelected("123");
    pshSentPkt.setSourceAddress(newCon.getConnectionAddresses().getAddressOne());
    pshSentPkt.setTcpConnection(newCon);
    var resultPsh = underTest.isVisible(pshSentPkt, filtersForm);
    var resultSyn = underTest.isVisible(synSentPkt, filtersForm);
    assertThat(resultPsh).isTrue();
    assertThat(resultSyn).isFalse();
  }

  @Test
  void isVisible_portRange() {
    var filtersForm = FiltersForm.getInstance();

    filtersForm.setPortRangeSelected("66-100");
    synSentPkt.setSourceAddress(new InternetAddress("", "", null, 101));
    synSentPkt.setDestinationAddress(new InternetAddress("", "", null, 101));
    pshSentPkt.setDestinationAddress(new InternetAddress("", "", null, 66));
    var resultPsh = underTest.isVisible(pshSentPkt, filtersForm);
    var resultSyn = underTest.isVisible(synSentPkt, filtersForm);
    assertThat(resultPsh).isTrue();
    assertThat(resultSyn).isFalse();
  }

  @Test
  void prettyPrintPacket() {
    var result = underTest.prettyPrintPacket(synSentPkt, FiltersForm.getInstance());

    //asserting the string minus the timestamp
    assertThat(result).containsIgnoringWhitespaces("""
                    <p> <a href="1:0:0:S:\
                    ConnectionAddresses {addressOne=InternetAddress{alphanumericalAddress='192', hostName='fish.com', pcap4jAddress=null, port=80},\
                     addressTwo=InternetAddress{alphanumericalAddress='333', hostName='host.com', pcap4jAddress=null, port=80}}"> \
                     2018-11-12""",
            "IPv4 333:80 > 192:80: Flags [S], seq 1, ack 0, win 50, options [2], length 0 </a></p>");

    var result2 = underTest.prettyPrintPacket(pshSentPkt, FiltersForm.getInstance());

    assertThat(result2)
      .contains("""
          <p> <a href="3:40:2:.P:ConnectionAddresses{addressOne=InternetAddress{alphanumericalAddress='192', hostName='fish.com',\
           pcap4jAddress=null, port=80}, addressTwo=InternetAddress{alphanumericalAddress='333', hostName='host.com', pcap4jAddress=null, port=80}}">\
          """,
        """
          IPv4 333:80 > 192:80: Flags [.P], seq 3, ack 2, win 50, options [], length 40 </a></p>""");
  }

  @Test
  void getStatusForPacket() {
    var result = underTest.getStatusForPacket(synSentPkt, connection);
    assertThat(result).isEqualTo(ConnectionStatus.SYN_SENT);

    var result2 = underTest.getStatusForPacket(synReceivedPkt, connection);
    assertThat(result2).isEqualTo(ConnectionStatus.SYN_RECEIVED);

    var result3 = underTest.getStatusForPacket(pshSentPkt, connection);
    assertThat(result3).isEqualTo(ConnectionStatus.ESTABLISHED);

    var result4 = underTest.getStatusForPacket(pshReceivedPkt, connection);
    assertThat(result4).isEqualTo(ConnectionStatus.ESTABLISHED);
  }

  @Test
  void getStatusForPacket_stateTraversalThroughFullConnection_finWait() {
    var result = ConnectionStatus.UNKNOWN;
    connection.setConnectionStatus(ConnectionStatus.UNKNOWN);
    var statusOrder = new ArrayList<ConnectionStatus>();
    for(EasyTCPacket pkt: connection.getPacketContainer().getPackets()) {
      result = underTest.getStatusForPacket(pkt, connection);
      statusOrder.add(result);
    }

    assertThat(statusOrder)
      .containsExactly(
      ConnectionStatus.SYN_SENT, ConnectionStatus.SYN_RECEIVED,
      ConnectionStatus.ESTABLISHED, ConnectionStatus.ESTABLISHED,
      ConnectionStatus.FIN_WAIT_1, ConnectionStatus.FIN_WAIT_2,
      ConnectionStatus.FIN_WAIT_2);
  }

  @Test
  void getStatusForPacket_stateTraversalThroughFullConnection_serverTerminates() {
    var result = ConnectionStatus.UNKNOWN;
    var serverTerminatesCon = TestUtils.getConnectionWithHandshakeAndFinCloseWait();
    serverTerminatesCon.setStatusAsOfPacketTraversal(ConnectionStatus.UNKNOWN);
    var statusOrder = new ArrayList<ConnectionStatus>();
    for(EasyTCPacket pkt: serverTerminatesCon.getPacketContainer().getPackets()) {
      result = underTest.getStatusForPacket(pkt, serverTerminatesCon);
      statusOrder.add(result);
    }

    assertThat(statusOrder)
      .containsExactly(
        ConnectionStatus.SYN_SENT, ConnectionStatus.SYN_RECEIVED,
        ConnectionStatus.ESTABLISHED, ConnectionStatus.ESTABLISHED,
        ConnectionStatus.CLOSE_WAIT, ConnectionStatus.LAST_ACK,
        ConnectionStatus.CLOSED);
  }

  @Test
  void getTcpFlagsForPacket() {
    var filters = FiltersForm.getInstance();
    filters.setShowHeaderFlags(true);
    filters.setShowAckAndSeqNumbers(true);
    filters.setShowLength(true);
    var result = underTest.getTcpFlagsForPacket(pshSentPkt, FiltersForm.getInstance());
    assertThat(result).isEqualTo("PSH 3 , ACK 2 Length 40");
    assertThat(underTest.getTcpFlagsForPacket(synSentPkt, FiltersForm.getInstance()))
      .isEqualTo("SYN 1  Length 0");

    filters.setShowHeaderFlags(false);
    filters.setShowAckAndSeqNumbers(false);
    filters.setShowLength(false);
    var result2 = underTest.getTcpFlagsForPacket(synSentPkt, FiltersForm.getInstance());
    assertThat(result2).isEqualTo("");

  }

  @Test
  void getTcpOptionsForPacket() {
    var result = underTest.getTcpOptionsForPacket(pshSentPkt, FiltersForm.getInstance());
    assertThat(result).isEqualTo("Win 50\n");
    FiltersForm.getInstance().setShowTcpOptions(true);
    var result2 = underTest.getTcpOptionsForPacket(synSentPkt, FiltersForm.getInstance());
    assertThat(result2).isEqualTo("Win 50\n<MSS 100 bytes >");
  }

  @Test
  void getConnectionTimestampForPacket() {
    synSentPkt.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.12345678"));
    var result = underTest.getConnectionTimestampForPacket(synSentPkt);
    assertThat(result).isEqualTo("0.000000 (0.0000)");

    pshSentPkt.setTimestamp(Timestamp.valueOf("2018-11-12 13:02:56.32345678"));
    var result2 = underTest.getConnectionTimestampForPacket(pshSentPkt);
    assertThat(result2).isEqualTo("0.200000 (0.2000)");
  }

  @Test
  void getSegmentLabel() {
    var result = underTest.getSegmentLabel(synSentPkt);
    assertThat(result).isEqualTo("Segment 1");

    var result2 = underTest.getSegmentLabel(pshSentPkt);
    assertThat(result2).isEqualTo("Segment 3");
  }
}