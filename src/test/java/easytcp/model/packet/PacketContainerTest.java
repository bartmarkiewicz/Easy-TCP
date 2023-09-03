package easytcp.model.packet;

import easytcp.TestUtils;
import easytcp.model.TCPFlag;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption;
import org.pcap4j.packet.TcpWindowScaleOption;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PacketContainerTest {

  private PacketContainer underTest;
  private EasyTCPacket synSentPacket;
  private EasyTCPacket synReceivedPacket;
  private EasyTCPacket pshPcktSent;
  private EasyTCPacket pshPcktReceived;
  private TCPConnection connection;
  private TcpWindowScaleOption windowScaleOpt = new TcpWindowScaleOption.Builder().length((byte) 3).build();
  private TcpMaximumSegmentSizeOption mssSentOpt =
      new TcpMaximumSegmentSizeOption.Builder().maxSegSize((short) 33).build();
  @BeforeEach
  void setUp() {
    //creates a packet container with some packets
    underTest = new PacketContainer();
    connection = TestUtils.createTCPConnection(true,
      TestUtils.createAddress("123.123", "fish.com"),
      TestUtils.createAddress("333.222", "otherfish.uk"));
    synSentPacket =
      TestUtils.createEasyTcpDataPacket(connection, true, 0L, 1L, 0, List.of(TCPFlag.SYN));
    synReceivedPacket =
      TestUtils.createEasyTcpDataPacket(
        connection, false, 1L, 2L, 0, List.of(TCPFlag.SYN, TCPFlag.ACK));

    pshPcktSent =
      TestUtils.createEasyTcpDataPacket(connection, true, 2L, 3L, 40, List.of(TCPFlag.PSH, TCPFlag.ACK));
    pshPcktSent.setTcpOptions(List.of(windowScaleOpt));

    pshPcktReceived =
      TestUtils.createEasyTcpDataPacket(
        connection, false, 43L, 4L, 2, List.of(TCPFlag.PSH, TCPFlag.ACK));
    synReceivedPacket.setTcpOptions(List.of(mssSentOpt));
    underTest.addPacketToContainer(synReceivedPacket);
    underTest.addPacketToContainer(pshPcktReceived);
    underTest.addPacketToContainer(synSentPacket);
    underTest.addPacketToContainer(pshPcktSent);
  }

  @Test
  void findPacketWithSeqNumber() {
    var result = underTest.findPacketsWithSeqNum(4L, false);
    assertThat(result).contains(pshPcktReceived);
    var result2 = underTest.findPacketsWithSeqNum(3L, true);
    assertThat(result2).contains(pshPcktSent);
  }

  @Test
  void getUniqueTcpOptions() {
    var result = underTest.getUniqueTcpOptions(true);
    assertThat(result).containsExactly(windowScaleOpt.getKind());

    var result2 = underTest.getUniqueTcpOptions(false);
    assertThat(result2).containsExactly(mssSentOpt.getKind());
  }

  @Test
  void findLatestPacketWithSeqNumberLessThan() {
    var result = underTest.findLatestPacketWithSeqNumberLessThan(3L, true);
    assertThat(result).contains(synSentPacket);

    var result2 = underTest.findLatestPacketWithSeqNumberLessThan(3L, false);
    assertThat(result2).contains(synReceivedPacket);
  }

  @Test
  void addPacketToContainer_assertSorted() {
    var newPktEarlierThanOthers = TestUtils.createEasyTcpDataPacket(connection, true, 1L, 1L, 20, List.of(TCPFlag.FIN));
    newPktEarlierThanOthers.setTimestamp(Timestamp.from(Instant.now().minus(400, ChronoUnit.MILLIS)));
    underTest.addPacketToContainer(newPktEarlierThanOthers);;

    assertThat(underTest.getPackets())
      .contains(newPktEarlierThanOthers,
        synSentPacket,
        synReceivedPacket,
        pshPcktSent,
        pshPcktReceived);
    assertThat(underTest.getPackets().get(0)).isEqualTo(newPktEarlierThanOthers);
  }

  @Test
  void getAllPacketsWithoutFlag() {
    var result = underTest.getAllPacketsWithoutFlag(TCPFlag.PSH, true);
    assertThat(result).containsExactly(synSentPacket);

    var result2 = underTest.getAllPacketsWithoutFlag(TCPFlag.SYN, false);
    assertThat(result2).containsExactly(pshPcktReceived);
  }

  @Test
  void findPacketsWithFlagOutGoingOrNot() {
    var result = underTest.findPacketsWithFlagOutGoingOrNot(TCPFlag.SYN);
    assertThat(result.get(true)).contains(synSentPacket);
    assertThat(result.get(false)).contains(synReceivedPacket);

    var result2 = underTest.findPacketsWithFlagOutGoingOrNot(TCPFlag.PSH);
    assertThat(result2.get(true)).contains(pshPcktSent);
    assertThat(result2.get(false)).contains(pshPcktReceived);
  }

  @Test
  void getPackets() {
    var temp = new ArrayList<>(underTest.getPackets());
    var tempSorted = temp.stream().sorted(Comparator.comparing(EasyTCPacket::getTimestamp)).toList();

    assertThat(underTest.getPackets())
      .containsExactly(tempSorted.get(0), tempSorted.get(1), tempSorted.get(2), tempSorted.get(3));
  }

  @Test
  void getOutgoingPackets() {
    var result = underTest.getOutgoingPackets();
    assertThat(result).containsExactly(synSentPacket, pshPcktSent);
  }

  @Test
  void getIncomingPackets() {
    var result = underTest.getIncomingPackets();
    assertThat(result).containsExactly(synReceivedPacket, pshPcktReceived);
  }

  @Test
  void clearPackets() {
    underTest.clearPackets();
    assertThat(underTest.getPackets()).isEmpty();
  }

  @Test
  void getBytesSentOrReceived() {
    var result = underTest.getBytesSentOrReceived(true);
    assertThat(result).isEqualTo(40);

    var result2 = underTest.getBytesSentOrReceived(false);
    assertThat(result2).isEqualTo(2);
  }

  @Test
  void findPacketWith() {
    var result = underTest.findPacketWith(1L, 0L, 0, "S");
    assertThat(result).contains(synSentPacket);

    var result2 = underTest.findPacketWith(2L, 1L, 0, ".S");
    assertThat(result2).contains(synReceivedPacket);
  }
}