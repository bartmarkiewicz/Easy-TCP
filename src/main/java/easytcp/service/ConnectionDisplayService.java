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

import java.text.NumberFormat;
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
    int currentIndex = 0;
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
    var tcpThreshold = filtersForm.getTcpStrategyThreshold();
    var delayedAckThreshold = tcpThreshold.getDelayedAckCountThreshold();
    var delayedAckTimeout = tcpThreshold.getDelayedAckCountMsThreshold();
    var lastOutgoingPacketHadData = false;
    var lastIncomingPacketHadData = false;
    var slowStartPossibilityReceiving = 0;
    var slowStartPossibilitySending = 0;
    var ackCounter = 0;
    var currentReceivingWindowSize = 0;
    var currentSendingWindowSize = 0;
    var consecutivePacketsRcvd = 0;
    var consecutivePacketsSent = 0;

    for(EasyTCPacket pkt: packetContainer.getPackets()) {
      //check for slow start
      if (pkt.getOutgoingPacket()) {
        currentReceivingWindowSize = 0;
        consecutivePacketsRcvd = 0;
        consecutivePacketsSent++;
        var previousSendingWindow = currentSendingWindowSize;
        currentSendingWindowSize += pkt.getDataPayloadLength();
        if (consecutivePacketsSent > 1
          && currentSendingWindowSize > previousSendingWindow * tcpThreshold.getSlowStartThreshold()
          && currentSendingWindowSize > 0
          && previousSendingWindow > 0) {
          slowStartPossibilitySending++;
          LOGGER.debug("Window size increased from %s to %s on outgoing, likely slow start"
            .formatted(previousSendingWindow, currentSendingWindowSize));
        }
      } else {
        currentSendingWindowSize = 0;
        consecutivePacketsRcvd++;
        consecutivePacketsSent = 0;
        var previousReceivingWindow = currentReceivingWindowSize;
        currentReceivingWindowSize += pkt.getDataPayloadLength();
        if (consecutivePacketsRcvd > 1
          && currentReceivingWindowSize > previousReceivingWindow * tcpThreshold.getSlowStartThreshold()
          && currentReceivingWindowSize > 0
          && previousReceivingWindow > 0) {
          slowStartPossibilityReceiving++;
          LOGGER.debug("Window size increased from %s to %s on incoming, likely slow start"
            .formatted(previousReceivingWindow, currentReceivingWindowSize));
        }
      }
    }

    while (currentIndex < packetContainer.getPackets().size()) {
      //detects the various tcp strategies
      var currentPacket = packetContainer.getPackets().get(currentIndex);
      var currentPacketFromStart = packetContainer.getPackets().get(0);
      var packetBeingAcked = packetContainer.findLatestPacketWithSeqNumberLessThan(currentPacket.getAckNumber() + currentPacket.getSequenceNumber(), currentPacket.getOutgoingPacket());

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
          LOGGER.debug("Delayed ack possibility + 1 duration - between ack and packet %s".formatted(Duration.between(
              packetBeingAcked.get().getTimestamp().toInstant(), currentPacket.getTimestamp().toInstant())
            .toMillis()));
        }
        if (!currentPacket.getOutgoingPacket() && packetBeingAcked.isPresent() && Duration.between(
            packetBeingAcked.get().getTimestamp().toInstant(), currentPacket.getTimestamp().toInstant())
          .toMillis() >= delayedAckTimeout) {
          delayedAckPossibilityIncoming++;
          LOGGER.debug("Delayed ack possibility + 1 duration - %s ".formatted(Duration.between(
              packetBeingAcked.get().getTimestamp().toInstant(), currentPacket.getTimestamp().toInstant())
            .toMillis()));
        }
      } else {
        ackCounter = 0;
      }


      if (currentPacket.getOutgoingPacket() && sendingMss.isPresent()) {
        var sendingMssBytes = ((TcpMaximumSegmentSizeOption) sendingMss.get()).getMaxSegSize();
        var nagleThreshold =
          (sendingMssBytes * filtersForm.getTcpStrategyThreshold().getNagleThresholdModifier());
        var outgoingPackets = packetContainer.getOutgoingPackets();
        var outGoingPacketIndx = outgoingPackets.indexOf(currentPacket);
        if (outGoingPacketIndx >= 0 && (outGoingPacketIndx + 1) < outgoingPackets.size()) {
          //if more data to sent
          if (currentPacket.getWindowSize() >= currentPacket.getDataPayloadLength()
            && currentPacket.getDataPayloadLength() >= nagleThreshold) {
            LOGGER.debug("Possibly nagle enabled on outgoing connection payload - %s, threshold %s, %s win size"
              .formatted(currentPacket.getDataPayloadLength(), sendingMssBytes, currentPacket.getWindowSize()));
            nagleAlgorithmPossibilityOutgoing++;
          } else if ((outGoingPacketIndx - 1) > 0){
            var previousPkt = outgoingPackets.get(outGoingPacketIndx - 1);
            var previousPktAckSeq = previousPkt.getAckNumber() + previousPkt.getDataPayloadLength();
            var acksForPreviousPacket = packetContainer.findPacketsWithSeqNum(previousPktAckSeq);
            if (acksForPreviousPacket.isEmpty()) {
              LOGGER.debug("No ack for previous packet so is not nagling here");
            } else {
              if (currentPacket.getTimestamp().getTime() > acksForPreviousPacket.get(0).getTimestamp().getTime()) {
                // this is probably right
                nagleAlgorithmPossibilityOutgoing++;
                LOGGER.debug("current packet checked timestamp %s, ack for previous outgoing packet timestamp %s"
                  .formatted(currentPacket.getTimestamp().toString(), acksForPreviousPacket.get(0).getTimestamp().toString()));
              } else {
                LOGGER.debug("Ack came after packet");
              }
            }
          }
        }
      }

      if (!currentPacket.getOutgoingPacket() && receivingMss.isPresent()) {
        var receivingMssBytes = ((TcpMaximumSegmentSizeOption) receivingMss.get()).getMaxSegSize();
        var nagleThreshold =
          (receivingMssBytes *filtersForm.getTcpStrategyThreshold().getNagleThresholdModifier());
        if (currentPacket.getDataPayloadLength() >= nagleThreshold) {
          LOGGER.debug("Possibly nagle enabled on incoming payload - %s, threshold %s, %s win size"
            .formatted(currentPacket.getDataPayloadLength(), nagleThreshold, currentPacket.getWindowSize()));
          if (packetBeingAcked.isPresent()) {
            LOGGER.debug("Other win size %s".formatted(packetBeingAcked.get().getWindowSize()));
          }
          nagleAlrogithmPossibilityIncoming++;
        }
      }

      currentIndex++;
    }

    var detectedTcpFeatures = 0;

    if (slowStartPossibilitySending > 1) { // (packetContainer.getOutgoingPackets().size()/2)) {
      detectedTcpFeatures++;
      stringBuilder.append("Detected tcp features\n");
      stringBuilder.append("Slow start is enabled on the client\n");
    }

    if (slowStartPossibilityReceiving > 1 ) { //(packetContainer.getIncomingPackets().size()/2)) {
      detectedTcpFeatures++;
      if (detectedTcpFeatures == 1) {
        stringBuilder.append("Detected tcp features\n");
      }
      stringBuilder.append("Slow start is enabled on the server\n");
    }

    if (delayedAckPossibilityIncoming > (packetContainer.getIncomingPackets().size()/2)) {
      detectedTcpFeatures++;
      if (detectedTcpFeatures == 1) {
        stringBuilder.append("Detected tcp features\n");
      }
      stringBuilder.append("Delayed ack is enabled on the client\n");
    }

    if (delayedAckPossibilityOutgoing > (packetContainer.getOutgoingPackets().size()/2)) {
      detectedTcpFeatures++;
      if (detectedTcpFeatures == 1) {
        stringBuilder.append("Detected tcp features\n");
      }
      stringBuilder.append("Delayed ack is enabled on the server\n");
    }

    if (sendingMss.isPresent() || receivingMss.isPresent()) {
      //check for nagle
      if (nagleAlgorithmPossibilityOutgoing > ((packetContainer.getOutgoingPackets().size()/3))) {
        detectedTcpFeatures++;
        if (detectedTcpFeatures == 1) {
          stringBuilder.append("Detected tcp features\n");
        }
        stringBuilder.append("Nagle's algorithm is enabled on the client\n");
      }

      if (nagleAlrogithmPossibilityIncoming > ((packetContainer.getIncomingPackets().size()/3))) {
        detectedTcpFeatures++;
        if (detectedTcpFeatures == 1) {
          stringBuilder.append("Detected tcp features\n");
        }
        stringBuilder.append("Nagle's algorithm is enabled on the server\n");
      }
    }

    var packetsSentRetransmissions = packetContainer.getPacketsCountRetransmissions(true);
    var packetsReceivedRetransmissions = packetContainer.getPacketsCountRetransmissions(false);
    var outgoingPackets = packetContainer.getOutgoingPackets();
    var incomingPackets = packetContainer.getIncomingPackets();
    var format = NumberFormat.getPercentInstance();

    //todo this isn't very accurate
    if (packetsSentRetransmissions > 0) {
      var packetLoss = (double) packetsSentRetransmissions / outgoingPackets.size();
      stringBuilder.append("Approximate packet loss on send %s \n"
        .formatted(format.format(packetLoss)));
    }

    if (packetsReceivedRetransmissions > 0) {
      var packetLoss = (double) packetsReceivedRetransmissions / incomingPackets.size();
      stringBuilder.append("Approximate packet loss on receive %s \n"
        .formatted(format.format(packetLoss)));
    }


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
