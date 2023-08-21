package easytcp.service;

import easytcp.model.TCPFlag;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.PacketContainer;
import easytcp.model.packet.TCPConnection;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ConnectionDisplayService {

  private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionDisplayService.class);


  public String getConnectionInformation(TCPConnection tcpConnection) {
    var sb = new StringBuilder();
    var filters = FiltersForm.getInstance();
    var packetContainer = tcpConnection.getPacketContainer();
    sb.append("""
      Connection status: %s
      """.formatted(tcpConnection.getConnectionStatus().getDisplayText()));
    if (filters.isShowGeneralInformation()) {
      sb.append("""
        Packets sent: %s
        Packets received: %s
        Host one: %s
        Host two: %s
        Port one : %s
        Port two : %s
        """.formatted(packetContainer.getOutgoingPackets().size(),
        packetContainer.getIncomingPackets().size(),
        tcpConnection.getHost().getAddressString(),
        tcpConnection.getHostTwo().getAddressString(),
        tcpConnection.getHost().getPort(),
        tcpConnection.getHostTwo().getPort()));
      sb.append("""
      Bytes sent %s
      Bytes received %s
      """.formatted(
        packetContainer.getBytesSentOrReceived(true),
        packetContainer.getBytesSentOrReceived(false)));
    }
    if (filters.isShowTcpFeatures()) {
      appendTcpConnectionFeatures(sb, tcpConnection);
    }
    if (filters.isShowTcpOptions()) {
      appendTcpConnectionOptions(sb, packetContainer);
    }

    if (filters.isShowHeaderFlags()) {
      var synMap = packetContainer.findPacketsWithFlagOutGoingOrNot(TCPFlag.SYN);
      var urgMap = packetContainer.findPacketsWithFlagOutGoingOrNot(TCPFlag.URG);
      var ackMap = packetContainer.findPacketsWithFlagOutGoingOrNot(TCPFlag.ACK);
      var pshMap = packetContainer.findPacketsWithFlagOutGoingOrNot(TCPFlag.PSH);
      var rstMap = packetContainer.findPacketsWithFlagOutGoingOrNot(TCPFlag.RST);
      var finMap = packetContainer.findPacketsWithFlagOutGoingOrNot(TCPFlag.FIN);
      if (!packetContainer.getPackets().isEmpty()) {
        sb.append("Packet flags sent/received\n");
        appendFlagString(sb, TCPFlag.SYN, synMap);
        appendFlagString(sb, TCPFlag.URG, urgMap);
        appendFlagString(sb, TCPFlag.ACK, ackMap);
        appendFlagString(sb, TCPFlag.PSH, pshMap);
        appendFlagString(sb, TCPFlag.RST, rstMap);
        appendFlagString(sb, TCPFlag.FIN, finMap);
      }
    }
    return sb.toString();
  }

  private void appendTcpConnectionFeatures(StringBuilder stringBuilder, TCPConnection connection) {
    var packetContainer = connection.getPacketContainer();
    int currentIndex = packetContainer.getPackets().size() - 1;
    int delayedAckPossibilityOutgoing = 0;
    int delayedAckPossibilityIncoming = 0;

    int nagleAlgorithmPossibilityOutgoing = 0;
    int nagleAlrogithmPossibilityIncoming = 0;
    var filtersForm = FiltersForm.getInstance();
    var mssPackets = packetContainer.findPacketsWithOption(TcpOptionKind.MAXIMUM_SEGMENT_SIZE)
      .stream()
      .collect(Collectors.partitioningBy(EasyTCPacket::getOutgoingPacket));
    var receivingMss = mssPackets.get(false).stream()
      .max(Comparator.comparing(EasyTCPacket::getTimestamp))
      .flatMap(pkt -> pkt.getTcpOptions()
        .stream()
        .filter(opt -> opt.getKind().equals(TcpOptionKind.MAXIMUM_SEGMENT_SIZE))
        .findFirst());
    var sendingMss = mssPackets.get(true).stream()
      .max(Comparator.comparing(EasyTCPacket::getTimestamp))
      .flatMap(pkt -> pkt.getTcpOptions()
        .stream()
        .filter(opt -> opt.getKind().equals(TcpOptionKind.MAXIMUM_SEGMENT_SIZE))
        .findFirst());
    var delayedAckThreshold = filtersForm.getTcpStrategyThreshold().getDelayedAckCountThreshold();
    var delayedAckTimeout = filtersForm.getTcpStrategyThreshold().getDelayedAckCountMsThreshold();
    var lastOutgoingPacketHadData = false;
    var lastIncomingPacketHadData = false;
    var ackCounter = 0;
    while (currentIndex >= 0) {
      //detects the various tcp strategies
      var currentPacket = packetContainer.getPackets().get(currentIndex);
      var packetBeingAcked = packetContainer.findLatestPacketWithSeqNumberLessThan(currentPacket.getAckNumber());

      if (packetBeingAcked.isPresent() && packetBeingAcked.get().getOutgoingPacket()) {
        lastOutgoingPacketHadData = packetBeingAcked.get().getDataPayloadLength() > 0;
      } else if (packetBeingAcked.isPresent()){
        lastIncomingPacketHadData = packetBeingAcked.get().getDataPayloadLength() > 0;
      }

      if (currentPacket.getTcpFlags().get(TCPFlag.ACK)) {
        if (currentPacket.getOutgoingPacket() && lastOutgoingPacketHadData) {
          ackCounter++;
          if (ackCounter >= delayedAckThreshold) {
            delayedAckPossibilityOutgoing++;
            ackCounter = 0;
          }
        } else if (!currentPacket.getOutgoingPacket() && lastIncomingPacketHadData) {
          ackCounter++;
          if (ackCounter >= delayedAckThreshold) {
            delayedAckPossibilityIncoming++;
            ackCounter = 0;
          }
        }
        if (currentPacket.getOutgoingPacket() && packetBeingAcked.isPresent() && Duration.between(
            packetBeingAcked.get().getTimestamp().toInstant(), currentPacket.getTimestamp().toInstant())
          .toMillis() >= delayedAckTimeout) {
          delayedAckPossibilityOutgoing++;
          LOGGER.debug("Delayed ack possibility + 1");
        }
        if (!currentPacket.getOutgoingPacket() && packetBeingAcked.isPresent() && Duration.between(
            packetBeingAcked.get().getTimestamp().toInstant(), currentPacket.getTimestamp().toInstant())
          .toMillis() >= delayedAckTimeout) {
          delayedAckPossibilityIncoming++;
          LOGGER.debug("Delayed ack possibility + 1");
        }
      } else {
        ackCounter = 0;
      }


      if (currentPacket.getOutgoingPacket() && sendingMss.isPresent()) {
        var sendingMssBytes = ((TcpMaximumSegmentSizeOption) sendingMss.get()).getMaxSegSize();
        var nagleThreshold =
          (sendingMssBytes - (sendingMssBytes*filtersForm.getTcpStrategyThreshold().getNagleThresholdModifier()));
        if (currentPacket.getDataPayloadLength() >= nagleThreshold) {
          LOGGER.debug("Possibly nagle enabled on outgoing connection");
          nagleAlgorithmPossibilityOutgoing++;
        }
      }
      if (!currentPacket.getOutgoingPacket() && receivingMss.isPresent()) {
        var receivingMssBytes = ((TcpMaximumSegmentSizeOption) receivingMss.get()).getMaxSegSize();
        var nagleThreshold =
          (receivingMssBytes - (receivingMssBytes*filtersForm.getTcpStrategyThreshold().getNagleThresholdModifier()));
        if (currentPacket.getDataPayloadLength() >= nagleThreshold) {
          LOGGER.debug("Possibly nagle enabled on outgoing connection");
          nagleAlrogithmPossibilityIncoming++;
        }
      }
      currentIndex--;
    }

    var detectedTcpFeatures = 0;

    if (delayedAckPossibilityIncoming > (packetContainer.getPackets().size()/2)) {
      detectedTcpFeatures++;
      stringBuilder.append("Detected tcp features\n");
      stringBuilder.append("Delayed ack is enabled on the client\n");
    }

    if (delayedAckPossibilityOutgoing > (packetContainer.getPackets().size()/2)) {
      detectedTcpFeatures++;
      if (detectedTcpFeatures == 1) {
        stringBuilder.append("Detected tcp features\n");
      }
      stringBuilder.append("Delayed ack is enabled on the server\n");
    }

    if (sendingMss.isPresent() || receivingMss.isPresent()) {
      //check for nagle
      if (nagleAlgorithmPossibilityOutgoing > ((packetContainer.getOutgoingPackets().size()/2))) {
        detectedTcpFeatures++;
        if (detectedTcpFeatures == 1) {
          stringBuilder.append("Detected tcp features\n");
        }
        stringBuilder.append("Nagle's algorithm is enabled on the client\n");
      }

      if (nagleAlrogithmPossibilityIncoming > ((packetContainer.getIncomingPackets().size()/2))) {
        detectedTcpFeatures++;
        if (detectedTcpFeatures == 1) {
          stringBuilder.append("Detected tcp features\n");
        }
        stringBuilder.append("Nagle's algorithm is enabled on the server\n");
      }
    }

    //check for slow start


  }

  private void appendTcpConnectionOptions(StringBuilder sb, PacketContainer packetContainer) {
    var uniqueOptionsOnConnection = packetContainer.getUniqueTcpOptions();
    for (TcpOptionKind opt : uniqueOptionsOnConnection) {
      if (opt.valueAsString().equals(TcpOptionKind.SACK_PERMITTED.valueAsString())) {
        sb.append("Selective acknowledgement (SACK) permitted\n");
      } else if (!opt.valueAsString().equals(TcpOptionKind.SACK.valueAsString())) {
        sb.append("%s\n".formatted(opt.name()));
      }
    }
  }

  private void appendFlagString(StringBuilder sb, TCPFlag flag, Map<Boolean, List<EasyTCPacket>> flagMap) {
    if (!flagMap.get(true).isEmpty() || !flagMap.get(false).isEmpty()) {
      sb.append("%s %s/%s\n".formatted(flag.name(), flagMap.get(true).size(), flagMap.get(false).size()));
    }
  }
}
