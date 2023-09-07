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


  /*Gets general information about the provided connection based on the display filters provided
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
        tcpConnection.getConnectionAddresses().addressOne().getAddressString(),
        tcpConnection.getConnectionAddresses().addressTwo().getAddressString(),
        tcpConnection.getConnectionAddresses().addressOne().getPort(),
        tcpConnection.getConnectionAddresses().addressTwo().getPort()));
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
      appendTcpConnectionOptions(sb, tcpConnection, true);
      appendTcpConnectionOptions(sb, tcpConnection, false);
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

  /* Attempts to detect various tcp strategies or features on the connection,
  and adds the text to the string builder used on the connection display panel
   */
  private void appendTcpStrategiesFound(StringBuilder sb,
                                        TCPConnection tcpConnection,
                                        TcpStrategyDetection tcpStrategyDetection) {
    var pktContainer = tcpConnection.getPacketContainer();
    var clientStrategiesCount = detectTcpStrategiesAndAppend(
      sb, tcpConnection, tcpStrategyDetection, pktContainer.getOutgoingPackets());
    var slowStartLst = detectSlowStart(pktContainer, tcpStrategyDetection);
    var clientSlowStartEnabled = slowStartLst.get(0)
      >= (pktContainer.getOutgoingPackets().size() * (tcpStrategyDetection.getPercentOfPackets()-0.1));
    if (clientStrategiesCount == 0 && clientSlowStartEnabled) {
      clientStrategiesCount++;
      sb.append("TCP features on the client\n");
      sb.append("Slow start is enabled\n");
    } else if (clientSlowStartEnabled) {
      clientStrategiesCount++;
      sb.append("Slow start is enabled\n");
    }
    if (clientStrategiesCount >= 1) {
      sb.append("\n");
    }
    var serverStrategiesCount = detectTcpStrategiesAndAppend(
      sb, tcpConnection, tcpStrategyDetection, pktContainer.getIncomingPackets());
    var serverSlowStartEnabled = slowStartLst.get(1)
      >= (pktContainer.getIncomingPackets().size() * (tcpStrategyDetection.getPercentOfPackets() - 0.1));
    if (serverStrategiesCount == 0 && serverSlowStartEnabled) {
      sb.append("TCP features on the server\n");
      sb.append("Slow start is enabled\n");
    } else if (serverSlowStartEnabled) {
      sb.append("Slow start is enabled\n");
    }

    if (serverStrategiesCount > 0) {
      sb.append("\n");
    }
  }


  private int detectTcpStrategiesAndAppend(StringBuilder sb,
                                           TCPConnection tcpConnection,
                                           TcpStrategyDetection tcpStrategyDetection,
                                           List<EasyTCPacket> sentOrReceivedPkts) {
    if (sentOrReceivedPkts.isEmpty()) {
      return 0;
    }
    var packetContainer = tcpConnection.getPacketContainer();

    //values which indicate signs of nagle and delayed ack respectively
    var naglePossibility = 0;
    var delayedAckPossibility = 0;

    var isClient = !sentOrReceivedPkts.isEmpty() ? sentOrReceivedPkts.get(0).getOutgoingPacket()
      : false;
    //gets mss that can be sent
    var receivingMSS = isClient
      ? tcpConnection.getMaximumSegmentSizeServer()
      : tcpConnection.getMaximumSegmentSizeClient();
    var nagleThreshold = receivingMSS != null ? (receivingMSS * tcpStrategyDetection.getNagleThresholdModifier())
      : 0; // the mss sensitivity modifier for signs of nagle

    var ackCounter = 0;

    //loops through all outgoing or received packets, based on weather the server or the client is being analysed.
    for (EasyTCPacket pkt: sentOrReceivedPkts) {
      //looks for signs of nagle on the packet
      naglePossibility += detectNagleOnPacket(pkt, packetContainer, nagleThreshold, sentOrReceivedPkts);

      //checks for delayed ack, returns array where index 0 = ack counter, index 1 = possibility
      var delayedAckResult = detectDelayedAckOnPacket(pkt, packetContainer, ackCounter, tcpStrategyDetection);
      ackCounter = delayedAckResult.get(0);
      delayedAckPossibility += delayedAckResult.get(1);
    }

    var percentDetectionThreshold = tcpStrategyDetection.getPercentOfPackets();
    var detectedTcpFeatures = 0;
    var onThe = sentOrReceivedPkts.get(0).getOutgoingPacket() ? "client" : "server";
    //checks the number of nagle possibilities against the percentage of the packets without the PSH flag
    // - which disables nagle and delayed ack
    // and checks if it is within the percent detection threshold
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

  /*Detects TCP slow start
   */
  private List<Integer> detectSlowStart(PacketContainer packetContainer, TcpStrategyDetection tcpStrategyDetection) {
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
        //checks for increasing window size, which is the payload sent before receiving an acknowledgement
        if (consecutivePacketsSent > 1
          && currentSendingWindowSize > previousSendingWindow * tcpStrategyDetection.getSlowStartThreshold()
          && currentSendingWindowSize > 0
          && previousSendingWindow > 0) {
          slowStartPossibilitySending+=2; //gets incremented by 2 since this won't be detected on every packet
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
          slowStartPossibilityReceiving+=2;
          LOGGER.debug("Window size increased from {} to {} on incoming, likely slow start",
            previousReceivingWindow, currentReceivingWindowSize);
        }
      }
    }
    return List.of(slowStartPossibilitySending, slowStartPossibilityReceiving);
  }

  //detects delayed ack behaviour for a packet
  private List<Integer> detectDelayedAckOnPacket(EasyTCPacket pkt,
                                                 PacketContainer packetContainer,
                                                 Integer ackCounter,
                                                 TcpStrategyDetection tcpStrategyDetection) {
    //latest ack
    var packetBeingAcked = packetContainer.findLatestPacketWithSeqNumberLessThan(
      pkt.getAckNumber() - pkt.getDataPayloadLength(), !pkt.getOutgoingPacket());
    var lastOutgoingPacketHadData = false;
    var delayedAckThreshold = tcpStrategyDetection.getDelayedAckCountThreshold();
    var delayedAckTimeoutThreshold = tcpStrategyDetection.getDelayedAckCountMsThreshold();
    var delayedAckPossibility = 0;
    var lastReceivedPkt = packetContainer.findPreviousPacketReceived(pkt);
    if (lastReceivedPkt.isPresent()) {
      //it should look if there were multiple data packets before an ack was sent
      lastOutgoingPacketHadData = lastReceivedPkt.get().getDataPayloadLength() > 0;
      if (pkt.getTcpFlags().get(TCPFlag.ACK) && pkt.getDataPayloadLength() > 0) {
        if (lastOutgoingPacketHadData) {
          ackCounter++;
          if (ackCounter >= delayedAckThreshold) {
            delayedAckPossibility += 0.5;
            //has less of a weight due to likelihood of it meeting the delayed ack threshold due to other factors
            ackCounter = 0;
          }
        }
      }
    } else {
      ackCounter = 0;
    }
    if (packetBeingAcked.isPresent()
      && Duration.between(packetBeingAcked.get().getTimestamp().toInstant(), pkt.getTimestamp().toInstant())
      .toMillis() >= delayedAckTimeoutThreshold) {
      //checks if the delay before sending an ack is greater than the timeout threshold
      //Basically checks if the ack was delayed
      delayedAckPossibility++;
      LOGGER.debug("Delayed ack possibility + 1 duration - between ack and packet {}", Duration.between(
          packetBeingAcked.get().getTimestamp().toInstant(), pkt.getTimestamp().toInstant())
        .toMillis());
    }

    return  List.of(ackCounter, delayedAckPossibility);
  }

  /*
   * Checks for signs of nagle on a packet
   */
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

    //if the packet has been acked, and there is mss
    if (packetIndx >= 0 && recentAckedPkt.isPresent() && nagleThreshold > 0) {
      //if mss is null, when the packet for it hasn't been captured, the captured nagle threshold is 0,
      // there is no possibility of detecting nagle through checking the payload
      naglePossiblity = checkIfPayloadNearMss(
        pkt, nagleThreshold, naglePossiblity, windowSizeScale * recentAckedPkt.get().getWindowSize());
    }
    if ((packetIndx - 1) > 0) {
      //checks if previous packet sent by the host has been acked before the current packet has been sent
      var previousPkt = packets.get(packetIndx - 1);
      var previousPktAckSeq = previousPkt.getAckNumber() + previousPkt.getDataPayloadLength();
      var acksForPreviousPacket = packetContainer.findPacketsWithSeqNum(
        previousPktAckSeq, !pkt.getOutgoingPacket());
      naglePossiblity = checkIfPacketSentAfterAck(pkt, acksForPreviousPacket, naglePossiblity);
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
      //if current packet is being sent after the ack for the previous packet
      if (pkt.getTimestamp().after(acksForPreviousPacket.get(0).getTimestamp())) {
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
      && pkt.getDataPayloadLength() >= nagleThreshold) { //if sending near MSS, likely nagle enabled
      LOGGER.debug("Possibly nagle enabled on outgoing connection payload - {}, threshold {}, {} win size",
        pkt.getDataPayloadLength(), nagleThreshold, pkt.getWindowSize());
      naglePossiblity++;
    }
    return naglePossiblity;
  }

  //Appends tcp connection options to the string builder used on the selected connection display panel
  private void appendTcpConnectionOptions(StringBuilder sb, TCPConnection connection, boolean outgoingCon) {
    var uniqueOptionsOnConnection = connection.getPacketContainer().getUniqueTcpOptions(outgoingCon);
    var counter = 0;
    for (TcpOptionKind opt : uniqueOptionsOnConnection) {
      if (opt.valueAsString().equals(TcpOptionKind.SACK_PERMITTED.valueAsString())) {
        counter++;
        if (counter <= 1) {
          sb.append("TCP options on the %s".formatted(outgoingCon ? "Client" : "Server"));
        }
        sb.append("SACK permitted\n");
      } else if (opt.valueAsString().equals(TcpOptionKind.WINDOW_SCALE.valueAsString())) {
        if (outgoingCon && connection.getWindowScaleClient() != null) {
          counter++;
          if (counter <= 1) {
            sb.append("Client TCP options\n");
          }
          sb.append("Window scale - %s\n".formatted(connection.getWindowScaleClient()));
        } else if (connection.getWindowScaleServer() != null) {
          counter++;
          if (counter <= 1) {
            sb.append("%s TCP options\n".formatted(outgoingCon ? "Client" : "Server"));
          }
          sb.append("Window scale - %s\n".formatted(connection.getWindowScaleServer()));
        }
      } else if (opt.valueAsString().equals(TcpOptionKind.MAXIMUM_SEGMENT_SIZE.valueAsString())) {

        if (outgoingCon && connection.getMaximumSegmentSizeClient() != null) {
          if (counter <= 1) {
            counter++;
            sb.append("Client TCP options\n");
          }
          sb.append("MSS - %s\n".formatted(connection.getMaximumSegmentSizeClient()));
        } else if (connection.getMaximumSegmentSizeServer() != null) {
          counter++;
          if (counter <= 1) {
            sb.append("%s TCP options\n".formatted(outgoingCon ? "Client" : "Server"));
          }
          sb.append("MSS - %s\n".formatted(connection.getMaximumSegmentSizeServer()));
        }
      }
    }
    if (counter > 0) {
      sb.append("\n");
    }
  }

  //Appends tcp flag counts onto the connection display string builder
  private void appendFlagString(StringBuilder sb, TCPFlag flag, Map<Boolean, List<EasyTCPacket>> flagMap) {
    if (!flagMap.get(true).isEmpty() || !flagMap.get(false).isEmpty()) {
      sb.append("%s %s/%s\n".formatted(flag.name(), flagMap.get(true).size(), flagMap.get(false).size()));
    }
  }
}
