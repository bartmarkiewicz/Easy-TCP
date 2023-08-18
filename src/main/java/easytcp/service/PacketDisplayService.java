package easytcp.service;

import easytcp.model.TCPFlag;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.TCPConnection;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketDisplayService {
  private static final Logger LOGGER = LoggerFactory.getLogger(PacketDisplayService.class);
  public boolean isVisible(EasyTCPacket packet, FiltersForm filtersForm) {
    var matchesFilter = true;

    switch (packet.getiPprotocol()) {
      case IPV4 ->
        matchesFilter = filtersForm.isShowIpv4();
      case IPV6 ->
        matchesFilter = filtersForm.isShowIpv6();
    }

    if (filtersForm.getSelectedConnection() != null
      && !(packet.getDestinationAddress().equals(filtersForm.getSelectedConnection().getHost())
      || packet.getSourceAddress().equals(filtersForm.getSelectedConnection().getHost()))) {
      matchesFilter = false;
      return matchesFilter;
    }

    if (!Strings.isBlank(filtersForm.getHostSelected())) {
      //filter by text ip/host
      var temp = filtersForm.getHostSelected().replace(" ", "").replace("/", "");
      matchesFilter = packet.getDestinationAddress().getAddressString().contains(temp)
        || packet.getSourceAddress().getAddressString().contains(temp)
        || packet.getDestinationAddress().getAlphanumericalAddress().contains(temp)
        || packet.getSourceAddress().getAlphanumericalAddress().contains(temp);
    }

    if (!Strings.isBlank(filtersForm.getPortRangeSelected())) {
      var temp = filtersForm.getPortRangeSelected().replace(" ", "");
      var twoPorts = temp.split("-");
      var dstPort = packet.getDestinationAddress().getPort();
      var srcPort = packet.getSourceAddress().getPort();
      try {
        if (twoPorts.length == 2) {
          var minPort = Integer.parseInt(twoPorts[0]);
          var maxPort = Integer.parseInt(twoPorts[1]);
          matchesFilter = (dstPort <= maxPort && dstPort >= minPort)
            || (srcPort <= maxPort && srcPort >= minPort);
        } else if (twoPorts.length == 1) {
          var selectedPort = Integer.parseInt(twoPorts[0]);
          matchesFilter = (dstPort == selectedPort)
            || (srcPort == selectedPort);
        }
      } catch (Exception e) {
        LOGGER.error("Text input into the port field");
      }
    }

    return matchesFilter;
  }

  public String prettyPrintPacket(EasyTCPacket packet, FiltersForm filtersForm) {
    return """
      %s %s %s:%s> %s:%s: Flags [%s], seq %s, ack %s, win %s, options [%s], length %s
      """
      .formatted(
        packet.getTimestamp().toString(),
        packet.getiPprotocol().getDisplayName(),
        filtersForm.isResolveHostnames() ? packet.getSourceAddress().getAddressString() : packet.getSourceAddress().getAlphanumericalAddress(),
        packet.getSourceAddress().getPort(),
        filtersForm.isResolveHostnames() ?  packet.getDestinationAddress().getAddressString() : packet.getDestinationAddress().getAlphanumericalAddress(),
        packet.getDestinationAddress().getPort(),
        packet.getTcpFlagsDisplayable(),
        packet.getSequenceNumber(),
        packet.getAckNumber(),
        packet.getWindowSize(),
        packet.getTcpOptionsDisplayable(),
        packet.getDataPayloadLength()
      );
  }

  public String getStatusLabelForPacket(EasyTCPacket pkt, TCPConnection tcpConnection) {
    var packetBeingAcked =
      tcpConnection.getPacketContainer()
        .findPacketWithSeqNumber(pkt.getSequenceNumber());
    var currentPacketFlags = pkt.getTcpFlags();

    if (tcpConnection.getConnectionStatus() == null) {
      tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
      return ConnectionStatus.CLOSED.getDisplayText();
    }
    switch (tcpConnection.getConnectionStatus()) {
      case CLOSED -> {
        //determine initial connection status
        if (currentPacketFlags.get(TCPFlag.SYN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
          return ConnectionStatus.SYN_SENT.getDisplayText();
        } else if (currentPacketFlags.get(TCPFlag.PSH)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.PSH)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);

          return ConnectionStatus.ESTABLISHED.getDisplayText();
        } else if (currentPacketFlags.get(TCPFlag.FIN) || currentPacketFlags.get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);

          return ConnectionStatus.CLOSED.getDisplayText();
        } else if (currentPacketFlags.get(TCPFlag.SYN)
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
          return ConnectionStatus.SYN_RECEIVED.getDisplayText();
        }
      }
      case SYN_SENT -> {
        LOGGER.debug("SYN SENT");
        if (currentPacketFlags.get(TCPFlag.SYN)
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
          return ConnectionStatus.SYN_RECEIVED.getDisplayText();
        } else if (currentPacketFlags.get(TCPFlag.SYN)) {
          // simultaneous open
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);

          return ConnectionStatus.SYN_RECEIVED.getDisplayText();
        } else if (currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);

          return ConnectionStatus.ESTABLISHED.getDisplayText();
        }
      }
      case SYN_RECEIVED -> {
        LOGGER.debug("SYN received");
        if (!pkt.getOutgoingPacket()
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);

          return ConnectionStatus.ESTABLISHED.getDisplayText();
        }
      }
      case ESTABLISHED -> {
        LOGGER.debug("Established");
        if (!pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSE_WAIT);

          return ConnectionStatus.CLOSE_WAIT.getDisplayText();
        } else if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_1);

          return ConnectionStatus.FIN_WAIT_1.getDisplayText();
        } else if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSE_WAIT);

          return ConnectionStatus.CLOSE_WAIT.getDisplayText();
        }
      }
      case CLOSE_WAIT -> {
        LOGGER.debug("close wait");
        if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.LAST_ACK);

          return ConnectionStatus.LAST_ACK.getDisplayText();
        }
      }
      case LAST_ACK -> {
        LOGGER.debug("last ack");

        if (!pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);

          return ConnectionStatus.CLOSED.getDisplayText();
        }
      }
      case FIN_WAIT_1 -> {
        LOGGER.debug("fin wait");

        if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)
          && !packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSING);

          return ConnectionStatus.CLOSING.getDisplayText();
        } else if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.TIME_WAIT);

          return ConnectionStatus.TIME_WAIT.getDisplayText();
        } else if (!pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_2);

          return ConnectionStatus.FIN_WAIT_2.getDisplayText();
        }
      }
      case FIN_WAIT_2 -> {
        LOGGER.debug("fin wait 2");

        if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.TIME_WAIT);

          return ConnectionStatus.TIME_WAIT.getDisplayText();
        }
      }
      case TIME_WAIT -> LOGGER.debug("time wait");
    }

    return "Fish";
  }

  public String getTcpFlagsForPacket(EasyTCPacket pkt, FiltersForm filtersForm) {
    var flags = pkt.getTcpFlags();
    var sb = new StringBuilder();
    var flagCount = 0;
    if (filtersForm.isShowHeaderFlags() && flags.get(TCPFlag.PSH)) {
      flagCount++;
      sb.append("PSH");
    }

    if (filtersForm.isShowHeaderFlags() && flags.get(TCPFlag.SYN)) {
      if (flagCount > 0) {
        sb.append(", ");
      }
      flagCount++;
      sb.append("SYN".formatted(pkt.getSequenceNumber()));
    }

    if (filtersForm.isShowAckAndSeqNumbers()) {
      sb.append(" %s ".formatted(pkt.getSequenceNumber()));
    }

    if (filtersForm.isShowHeaderFlags() && flags.get(TCPFlag.ACK)) {
      if (flagCount > 0) {
        sb.append(", ");
      }
      flagCount++;

      sb.append("ACK");
    }
    if (filtersForm.isShowAckAndSeqNumbers() && flags.get(TCPFlag.ACK)) {
      sb.append(" %s".formatted(pkt.getAckNumber()));
    }

    return sb.toString();
  }
}
