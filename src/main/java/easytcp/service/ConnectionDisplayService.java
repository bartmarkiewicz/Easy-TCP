package easytcp.service;

import easytcp.model.TCPFlag;
import easytcp.model.TcpStrategyDetection;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.PacketContainer;
import easytcp.model.packet.TCPConnection;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/*Service to return strings for the purpose of displaying a connection on the frontend.
 */
public class ConnectionDisplayService {

  private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionDisplayService.class);


  /*Gets information about the provided connection based on the filters provided
   */
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
      appendTcpStrategiesFound(sb, tcpConnection, filters.getTcpStrategyThreshold());
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

  /* Attempts to detect various tcp strategies or features on the connection
   */
  private void appendTcpStrategiesFound(StringBuilder sb,
                                        TCPConnection tcpConnection,
                                        TcpStrategyDetection tcpStrategyDetection) {
    var pktContainer = tcpConnection.getPacketContainer();
    var clientStrategiesCount = detectTcpStrategiesAndAppend(
      sb, tcpConnection, tcpStrategyDetection, pktContainer.getOutgoingPackets());
    var slowStartLst = detectSlowStart(pktContainer, tcpStrategyDetection);
    var clientSlowStartEnabled = slowStartLst.get(0)
      >= (pktContainer.getOutgoingPackets().size() * tcpStrategyDetection.getPercentOfPackets());
    if (clientStrategiesCount == 0 && clientSlowStartEnabled) {
      sb.append("TCP features on the client\n");
      sb.append("Slow start is enabled\n");
    } else if (clientSlowStartEnabled) {
      sb.append("Slow start is enabled\n");
    }

    var serverStrategiesCount = detectTcpStrategiesAndAppend(
      sb, tcpConnection, tcpStrategyDetection, pktContainer.getIncomingPackets());
    var serverSlowStartEnabled = slowStartLst.get(1)
      >= (pktContainer.getIncomingPackets().size() * tcpStrategyDetection.getPercentOfPackets());
    if (serverStrategiesCount == 0 && serverSlowStartEnabled) {
      sb.append("TCP features on the server\n");
      sb.append("Slow start is enabled\n");
    } else if (serverSlowStartEnabled) {
      sb.append("Slow start is enabled\n");
    }
  }


  private int detectTcpStrategiesAndAppend(StringBuilder sb,
                                           TCPConnection tcpConnection,
                                           TcpStrategyDetection tcpStrategyDetection,
                                           List<EasyTCPacket> sentOrReceivedPkts) {
    var packetContainer = tcpConnection.getPacketContainer();
    var naglePossibility = 0;
    var delayedAckPossibility = 0;
    var isClient = sentOrReceivedPkts.size() > 0 ? sentOrReceivedPkts.get(0).getOutgoingPacket()
      : false;
    var receivingMSS = isClient
      ? tcpConnection.getMaximumSegmentSizeServer()
      : tcpConnection.getMaximumSegmentSizeClient();
    var nagleThreshold = receivingMSS != null ? (receivingMSS * tcpStrategyDetection.getNagleThresholdModifier())
      : 0;
    var ackCounter = 0;

    for (EasyTCPacket pkt: sentOrReceivedPkts) {
      if (nagleThreshold > 0) {
        naglePossibility += detectNagleOnPacket(pkt, packetContainer, nagleThreshold, sentOrReceivedPkts);
      }
      //checks for delayed ack, returns array where index 0 = ack counter, index 1 = possibility
      var delayedAckResult = detectDelayedAckOnPacket(pkt, packetContainer, ackCounter, tcpStrategyDetection);
      ackCounter = delayedAckResult.get(0);
      delayedAckPossibility += delayedAckResult.get(1);
    }

    var percentDetectionThreshold = tcpStrategyDetection.getPercentOfPackets();
    var detectedTcpFeatures = 0;
    var onThe = sentOrReceivedPkts.get(0).getOutgoingPacket() ? "client" : "server";
    if (nagleThreshold > 0
      && naglePossibility > (packetContainer.getAllPacketsWithoutFlag(TCPFlag.PSH, isClient).size() * percentDetectionThreshold)) {
      detectedTcpFeatures++;
      sb.append("TCP features on the %s \n".formatted(onThe));
      sb.append("Nagle's algorithm is enabled \n");
    }
    if (delayedAckPossibility > (packetContainer.getAllPacketsWithoutFlag(TCPFlag.PSH, isClient).size() * percentDetectionThreshold)) {
      detectedTcpFeatures++;
      if (detectedTcpFeatures == 1) {
        sb.append("TCP features on the %s \n".formatted(onThe));
      }
      sb.append("Delayed ack is enabled \n");
    }
    return detectedTcpFeatures;
  }

  public List<Integer> detectSlowStart(PacketContainer packetContainer, TcpStrategyDetection tcpStrategyDetection) {
    int currentIndex = 0;
    var slowStartPossibilityReceiving = 0;
    var slowStartPossibilitySending = 0;
    var currentReceivingWindowSize = 0;
    var currentSendingWindowSize = 0;
    var consecutivePacketsRcvd = 0;
    var consecutivePacketsSent = 0;
    for(;currentIndex < packetContainer.getPackets().size(); currentIndex++) {
      //check for slow start
      var pkt = packetContainer.getPackets().get(currentIndex);
      if (pkt.getOutgoingPacket()) {
        currentReceivingWindowSize = 0;
        consecutivePacketsRcvd = 0;
        consecutivePacketsSent++;
        var previousSendingWindow = currentSendingWindowSize;
        currentSendingWindowSize += pkt.getDataPayloadLength();
        if (consecutivePacketsSent > 1
          && currentSendingWindowSize > previousSendingWindow * tcpStrategyDetection.getSlowStartThreshold()
          && currentSendingWindowSize > 0
          && previousSendingWindow > 0) {
          slowStartPossibilitySending++;
          LOGGER.debug("Window size increased from {} to {} on outgoing, likely slow start",
            previousSendingWindow, currentSendingWindowSize);
        }
      } else {
        currentSendingWindowSize = 0;
        consecutivePacketsRcvd++;
        consecutivePacketsSent = 0;
        var previousReceivingWindow = currentReceivingWindowSize;
        currentReceivingWindowSize += pkt.getDataPayloadLength();
        if (consecutivePacketsRcvd > 1
          && currentReceivingWindowSize > previousReceivingWindow * tcpStrategyDetection.getSlowStartThreshold()
          && currentReceivingWindowSize > 0
          && previousReceivingWindow > 0) {
          slowStartPossibilityReceiving++;
          LOGGER.debug("Window size increased from {} to {} on incoming, likely slow start",
            previousReceivingWindow, currentReceivingWindowSize);
        }
      }
    }
    return List.of(slowStartPossibilitySending, slowStartPossibilityReceiving);
  }

  private List<Integer> detectDelayedAckOnPacket(EasyTCPacket pkt,
                                             PacketContainer packetContainer,
                                             Integer ackCounter,
                                             TcpStrategyDetection tcpStrategyDetection) {
    //latest ack
    var packetBeingAcked = packetContainer.findLatestPacketWithSeqNumberLessThan(
      pkt.getAckNumber() + pkt.getSequenceNumber(), pkt.getOutgoingPacket());
    var lastOutgoingPacketHadData = false;
    var delayedAckThreshold = tcpStrategyDetection.getDelayedAckCountThreshold();
    var delayedAckTimeoutThreshold = tcpStrategyDetection.getDelayedAckCountMsThreshold();
    var delayedAckPossibility = 0;
    if (packetBeingAcked.isPresent()) {
      lastOutgoingPacketHadData = packetBeingAcked.get().getDataPayloadLength() > 0;
      if (pkt.getTcpFlags().get(TCPFlag.ACK)) {
        if (lastOutgoingPacketHadData) {
          ackCounter++;
          if (ackCounter >= delayedAckThreshold) {
            delayedAckPossibility++;
            ackCounter = 0;
          }
        }
        if (Duration.between(packetBeingAcked.get().getTimestamp().toInstant(), pkt.getTimestamp().toInstant())
          .toMillis() >= delayedAckTimeoutThreshold) {
          delayedAckPossibility++;
          LOGGER.debug("Delayed ack possibility + 1 duration - between ack and packet {}", Duration.between(
              packetBeingAcked.get().getTimestamp().toInstant(), pkt.getTimestamp().toInstant())
            .toMillis());
        }
      } else {
        ackCounter = 0;
      }
    }
    return  List.of(ackCounter, delayedAckPossibility);
  }

  private int detectNagleOnPacket(EasyTCPacket pkt,
                                  PacketContainer packetContainer,
                                  double nagleThreshold,
                                  List<EasyTCPacket> packets) {
    var naglePossiblity = 0;
    var packetIndx = packets.indexOf(pkt);
    var windowSizeScale = pkt.getOutgoingPacket()
      ? pkt.getTcpConnection().getWindowScaleServer()
      : pkt.getTcpConnection().getWindowScaleClient();
    if (windowSizeScale == null) {
      windowSizeScale = 1;
    }
    var recentAckedPkt = packetContainer.findLatestPacketWithSeqNumberLessThan(
      pkt.getAckNumber(), !pkt.getOutgoingPacket());

    if (packetIndx >= 0 && (packetIndx + 1) < packets.size()) {
      if (recentAckedPkt.isPresent()) {
        naglePossiblity = checkIfPayloadNearMss(
          pkt, nagleThreshold, naglePossiblity, windowSizeScale * recentAckedPkt.get().getWindowSize());
      }
      if ((packetIndx - 1) > 0) {
        //checks if previous packet
        var previousPkt = packets.get(packetIndx - 1);
        var previousPktAckSeq = previousPkt.getAckNumber() + previousPkt.getDataPayloadLength();
        var acksForPreviousPacket = packetContainer.findPacketsWithSeqNum(
          previousPktAckSeq);
        naglePossiblity = checkIfPacketSentAfterAck(pkt, acksForPreviousPacket, naglePossiblity);
      }
    }
    if (naglePossiblity == 2) {
      LOGGER.debug("Very likely nagle involved here");
    }
    return naglePossiblity;
  }

  private int checkIfPacketSentAfterAck(EasyTCPacket pkt, List<EasyTCPacket> acksForPreviousPacket, int naglePossiblity) {
    if (acksForPreviousPacket.isEmpty()) {
      LOGGER.debug("No ack for previous packet so is not nagling here");
    } else {
      if (pkt.getTimestamp().getTime() > acksForPreviousPacket.get(0).getTimestamp().getTime()) {
        // this is probably right
        naglePossiblity++;
        LOGGER.debug("current packet checked timestamp {}, ack for previous outgoing packet timestamp {}",
          pkt.getTimestamp(), acksForPreviousPacket.get(0).getTimestamp());
      } else {
        LOGGER.debug("Ack came after packet");
      }
    }
    return naglePossiblity;
  }

  private int checkIfPayloadNearMss(EasyTCPacket pkt, double nagleThreshold, int naglePossiblity, int windowSize) {
    if (windowSize >= pkt.getDataPayloadLength()
      && pkt.getDataPayloadLength() >= nagleThreshold) { //if sending near MSS
      LOGGER.debug("Possibly nagle enabled on outgoing connection payload - {}, threshold {}, {} win size",
        pkt.getDataPayloadLength(), nagleThreshold, pkt.getWindowSize());
      naglePossiblity++;
    }
    return naglePossiblity;
  }

  /*Appends any detected tcp connection strategies or features spotted
   * todo remove
   */
//  private void appendTcpConnectionFeatures(StringBuilder stringBuilder, TCPConnection connection) {
//    var packetContainer = connection.getPacketContainer();
//    int currentIndex = 0;
//    int delayedAckPossibilityOutgoing = 0;
//    int delayedAckPossibilityIncoming = 0;
//    int nagleAlgorithmPossibilityOutgoing = 0;
//    int nagleAlrogithmPossibilityIncoming = 0;
//    var filtersForm = FiltersForm.getInstance();
//    var mssPackets = packetContainer.findPacketsWithOption(TcpOptionKind.MAXIMUM_SEGMENT_SIZE)
//      .stream()
//      .collect(Collectors.partitioningBy(EasyTCPacket::getOutgoingPacket));
//    var receivingMss = mssPackets.get(true).stream()
//      .max(Comparator.comparing(EasyTCPacket::getTimestamp))
//      .flatMap(pkt -> pkt.getTcpOptions()
//        .stream()
//        .filter(opt -> opt.getKind().equals(TcpOptionKind.MAXIMUM_SEGMENT_SIZE))
//        .findFirst());
//    var sendingMss = mssPackets.get(false).stream()
//      .max(Comparator.comparing(EasyTCPacket::getTimestamp))
//      .flatMap(pkt -> pkt.getTcpOptions()
//        .stream()
//        .filter(opt -> opt.getKind().equals(TcpOptionKind.MAXIMUM_SEGMENT_SIZE))
//        .findFirst());
//    var tcpThreshold = filtersForm.getTcpStrategyThreshold();
//    var delayedAckThreshold = tcpThreshold.getDelayedAckCountThreshold();
//    var delayedAckTimeout = tcpThreshold.getDelayedAckCountMsThreshold();
//    var lastOutgoingPacketHadData = false;
//    var lastIncomingPacketHadData = false;
//    var slowStartPossibilityReceiving = 0;
//    var slowStartPossibilitySending = 0;
//    var ackCounter = 0;
//    var currentReceivingWindowSize = 0;
//    var currentSendingWindowSize = 0;
//    var consecutivePacketsRcvd = 0;
//    var consecutivePacketsSent = 0;
//
//    for(EasyTCPacket pkt: packetContainer.getPackets()) {
//      //check for slow start
//      if (pkt.getOutgoingPacket()) {
//        currentReceivingWindowSize = 0;
//        consecutivePacketsRcvd = 0;
//        consecutivePacketsSent++;
//        var previousSendingWindow = currentSendingWindowSize;
//        currentSendingWindowSize += pkt.getDataPayloadLength();
//        if (consecutivePacketsSent > 1
//          && currentSendingWindowSize > previousSendingWindow * tcpThreshold.getSlowStartThreshold()
//          && currentSendingWindowSize > 0
//          && previousSendingWindow > 0) {
//          slowStartPossibilitySending++;
//          LOGGER.debug("Window size increased from {} to {} on outgoing, likely slow start",
//            previousSendingWindow, currentSendingWindowSize);
//        }
//      } else {
//        currentSendingWindowSize = 0;
//        consecutivePacketsRcvd++;
//        consecutivePacketsSent = 0;
//        var previousReceivingWindow = currentReceivingWindowSize;
//        currentReceivingWindowSize += pkt.getDataPayloadLength();
//        if (consecutivePacketsRcvd > 1
//          && currentReceivingWindowSize > previousReceivingWindow * tcpThreshold.getSlowStartThreshold()
//          && currentReceivingWindowSize > 0
//          && previousReceivingWindow > 0) {
//          slowStartPossibilityReceiving++;
//          LOGGER.debug("Window size increased from {} to {} on incoming, likely slow start",
//            previousReceivingWindow, currentReceivingWindowSize);
//        }
//      }
//    }
//
//    while (currentIndex < packetContainer.getPackets().size()) {
//      //detects the various tcp strategies
//      var currentPacket = packetContainer.getPackets().get(currentIndex);
//      var packetBeingAcked = packetContainer.findLatestPacketWithSeqNumberLessThan(currentPacket.getAckNumber() + currentPacket.getSequenceNumber(), currentPacket.getOutgoingPacket());
//
//      if (packetBeingAcked.isPresent() && packetBeingAcked.get().getOutgoingPacket()) {
//        lastOutgoingPacketHadData = packetBeingAcked.get().getDataPayloadLength() > 0;
//      } else if (packetBeingAcked.isPresent()){
//        lastIncomingPacketHadData = packetBeingAcked.get().getDataPayloadLength() > 0;
//      }
//
//      if (currentPacket.getTcpFlags().get(TCPFlag.ACK)) {
//        if (currentPacket.getOutgoingPacket() && lastOutgoingPacketHadData) {
//          ackCounter++;
//          if (ackCounter >= delayedAckThreshold) {
//            delayedAckPossibilityOutgoing++;
//            ackCounter = 0;
//          }
//        } else if (!currentPacket.getOutgoingPacket() && lastIncomingPacketHadData) {
//          ackCounter++;
//          if (ackCounter >= delayedAckThreshold) {
//            delayedAckPossibilityIncoming++;
//            ackCounter = 0;
//          }
//        }
//        if (currentPacket.getOutgoingPacket() && packetBeingAcked.isPresent() && Duration.between(
//            packetBeingAcked.get().getTimestamp().toInstant(), currentPacket.getTimestamp().toInstant())
//          .toMillis() >= delayedAckTimeout) {
//          delayedAckPossibilityOutgoing++;
//          LOGGER.debug("Delayed ack possibility + 1 duration - between ack and packet %s".formatted(Duration.between(
//              packetBeingAcked.get().getTimestamp().toInstant(), currentPacket.getTimestamp().toInstant())
//            .toMillis()));
//        }
//        if (!currentPacket.getOutgoingPacket() && packetBeingAcked.isPresent() && Duration.between(
//            packetBeingAcked.get().getTimestamp().toInstant(), currentPacket.getTimestamp().toInstant())
//          .toMillis() >= delayedAckTimeout) {
//          delayedAckPossibilityIncoming++;
//          LOGGER.debug("Delayed ack possibility + 1 duration - %s ".formatted(Duration.between(
//              packetBeingAcked.get().getTimestamp().toInstant(), currentPacket.getTimestamp().toInstant())
//            .toMillis()));
//        }
//      } else {
//        ackCounter = 0;
//      }
//
//
//      if (currentPacket.getOutgoingPacket() && sendingMss.isPresent()) {
//        var sendingMssBytes = ((TcpMaximumSegmentSizeOption) sendingMss.get()).getMaxSegSize();
//        var nagleThreshold =
//          (sendingMssBytes * filtersForm.getTcpStrategyThreshold().getNagleThresholdModifier());
//        var outgoingPackets = packetContainer.getOutgoingPackets();
//        var outGoingPacketIndx = outgoingPackets.indexOf(currentPacket);
//        if (outGoingPacketIndx >= 0 && (outGoingPacketIndx + 1) < outgoingPackets.size()) {
//          //if more data to sent
//          if (currentPacket.getWindowSize() >= currentPacket.getDataPayloadLength()
//            && currentPacket.getDataPayloadLength() >= nagleThreshold) {
//            LOGGER.debug("Possibly nagle enabled on outgoing connection payload - {}, threshold {}, {} win size",
//              currentPacket.getDataPayloadLength(), sendingMssBytes, currentPacket.getWindowSize());
//            nagleAlgorithmPossibilityOutgoing++;
//          } else if ((outGoingPacketIndx - 1) > 0){
//            var previousPkt = outgoingPackets.get(outGoingPacketIndx - 1);
//            var previousPktAckSeq = previousPkt.getAckNumber() + previousPkt.getDataPayloadLength();
//            var acksForPreviousPacket = packetContainer.findPacketsWithSeqNum(previousPktAckSeq);
//            if (acksForPreviousPacket.isEmpty()) {
//              LOGGER.debug("No ack for previous packet so is not nagling here");
//            } else {
//              if (currentPacket.getTimestamp().getTime() > acksForPreviousPacket.get(0).getTimestamp().getTime()) {
//                // this is probably right
//                nagleAlgorithmPossibilityOutgoing++;
//                LOGGER.debug("current packet checked timestamp {}, ack for previous outgoing packet timestamp {}",
//                  currentPacket.getTimestamp(), acksForPreviousPacket.get(0).getTimestamp());
//              } else {
//                LOGGER.debug("Ack came after packet");
//              }
//            }
//          }
//        }
//      }
//
//      if (!currentPacket.getOutgoingPacket() && receivingMss.isPresent()) {
//        var receivingMssBytes = ((TcpMaximumSegmentSizeOption) receivingMss.get()).getMaxSegSize();
//        var nagleThreshold =
//          (receivingMssBytes *filtersForm.getTcpStrategyThreshold().getNagleThresholdModifier());
//        if (currentPacket.getDataPayloadLength() >= nagleThreshold) {
//          LOGGER.debug("Possibly nagle enabled on incoming payload - %s, threshold %s, %s win size"
//            .formatted(currentPacket.getDataPayloadLength(), nagleThreshold, currentPacket.getWindowSize()));
//          if (packetBeingAcked.isPresent()) {
//            LOGGER.debug("Other win size %s".formatted(packetBeingAcked.get().getWindowSize()));
//          }
//          nagleAlrogithmPossibilityIncoming++;
//        }
//      }
//
//      currentIndex++;
//    }
//
//    var detectedTcpFeatures = 0;
//
//    if (slowStartPossibilitySending > 1) { // (packetContainer.getOutgoingPackets().size()/2)) {
//      detectedTcpFeatures++;
//      stringBuilder.append("Detected tcp features\n");
//      stringBuilder.append("Slow start is enabled on the client\n");
//    }
//
//    if (slowStartPossibilityReceiving > 1 ) { //(packetContainer.getIncomingPackets().size()/2)) {
//      detectedTcpFeatures++;
//      if (detectedTcpFeatures == 1) {
//        stringBuilder.append("Detected tcp features\n");
//      }
//      stringBuilder.append("Slow start is enabled on the server\n");
//    }
//
//    if (delayedAckPossibilityIncoming > (packetContainer.getIncomingPackets().size()/2)) {
//      detectedTcpFeatures++;
//      if (detectedTcpFeatures == 1) {
//        stringBuilder.append("Detected tcp features\n");
//      }
//      stringBuilder.append("Delayed ack is enabled on the client\n");
//    }
//
//    if (delayedAckPossibilityOutgoing > (packetContainer.getOutgoingPackets().size()/2)) {
//      detectedTcpFeatures++;
//      if (detectedTcpFeatures == 1) {
//        stringBuilder.append("Detected tcp features\n");
//      }
//      stringBuilder.append("Delayed ack is enabled on the server\n");
//    }
//
//    if (sendingMss.isPresent() || receivingMss.isPresent()) {
//      //check for nagle
//      if (nagleAlgorithmPossibilityOutgoing > ((packetContainer.getOutgoingPackets().size()/3))) {
//        detectedTcpFeatures++;
//        if (detectedTcpFeatures == 1) {
//          stringBuilder.append("Detected tcp features\n");
//        }
//        stringBuilder.append("Nagle's algorithm is enabled on the client\n");
//      }
//
//      if (nagleAlrogithmPossibilityIncoming > ((packetContainer.getIncomingPackets().size()/3))) {
//        detectedTcpFeatures++;
//        if (detectedTcpFeatures == 1) {
//          stringBuilder.append("Detected tcp features\n");
//        }
//        stringBuilder.append("Nagle's algorithm is enabled on the server\n");
//      }
//    }
//
//    var packetsSentRetransmissions = packetContainer.getPacketsCountRetransmissions(true);
//    var packetsReceivedRetransmissions = packetContainer.getPacketsCountRetransmissions(false);
//    var outgoingPackets = packetContainer.getOutgoingPackets();
//    var incomingPackets = packetContainer.getIncomingPackets();
//    var format = NumberFormat.getPercentInstance();
//
//    //todo this isn't very accurate
//    if (packetsSentRetransmissions > 0) {
//      var packetLoss = (double) packetsSentRetransmissions / outgoingPackets.size();
//      stringBuilder.append("Approximate packet loss on send %s \n"
//        .formatted(format.format(packetLoss)));
//    }
//
//    if (packetsReceivedRetransmissions > 0) {
//      var packetLoss = (double) packetsReceivedRetransmissions / incomingPackets.size();
//      stringBuilder.append("Approximate packet loss on receive %s \n"
//        .formatted(format.format(packetLoss)));
//    }
//
//
//  }

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
