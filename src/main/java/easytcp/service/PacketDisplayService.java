package easytcp.service;

import easytcp.model.TCPFlag;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.TCPConnection;
import org.apache.logging.log4j.util.Strings;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption;
import org.pcap4j.packet.TcpWindowScaleOption;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

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
      && !(filtersForm.getSelectedConnection().getConnectionAddresses().equals(packet.getTcpConnection().getConnectionAddresses()))) {
      return false;
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

  /*
   *Creates a paragraph HTML element for the packet on the packet log text pane,
   * encodes the packet information in a link href to allow the hyper link listener to identify the packet clicked.
   * And returns a string in a tcpdump-like format.
   */
  public String prettyPrintPacket(EasyTCPacket packet, FiltersForm filtersForm) {
    return "<p>%s <a href=\"%s:%s:%s:%s:%s\"> %s %s %s:%s > %s:%s: Flags [%s], seq %s, ack %s, win %s, options [%s], length %s </a>%s</p>"
      .formatted(
        packet.getSelectedPacket() ? "<span>" : "",
        packet.getSequenceNumber(),
        packet.getDataPayloadLength(),
        packet.getAckNumber(), packet.getTcpFlagsDisplayable(), packet.getTcpConnection().getConnectionAddresses(),
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
        packet.getDataPayloadLength(),
        packet.getSelectedPacket() ? "</span>" : ""
      );
  }

  /* Gets the TCP connection status for the packet pkt at the stage where it was sent/received.
   */
  public ConnectionStatus getStatusForPacket(EasyTCPacket pkt, TCPConnection tcpConnection) {
    if (!ApplicationStatus.getStatus().isLiveCapturing().get() && pkt.getTcpConnectionStatusAsOfPacket() != null) {
      return pkt.getTcpConnectionStatusAsOfPacket();
    }
    var packetBeingAcked =
      tcpConnection.getPacketContainer()
        .findLatestPacketWithSeqNumberLessThan(pkt.getAckNumber()+pkt.getDataPayloadLength(), !pkt.getOutgoingPacket());
    var currentPacketFlags = pkt.getTcpFlags();
    if (tcpConnection.getStatusAsOfPacketTraversal() == null) {
      tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.UNKNOWN);
      LOGGER.debug("Null status, setting unknown as default");
    }

    if (currentPacketFlags.get(TCPFlag.RST)) {
      tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.REJECTED);
      pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.REJECTED);
      return ConnectionStatus.REJECTED;
    }

    //TCP connection state transitions
    switch (tcpConnection.getStatusAsOfPacketTraversal()) {
      case CLOSED -> {
        //determine initial connection status
        if (currentPacketFlags.get(TCPFlag.SYN) && !currentPacketFlags.get(TCPFlag.ACK)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_SENT);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_SENT);
          return ConnectionStatus.SYN_SENT;
        } else if (currentPacketFlags.get(TCPFlag.SYN)
          && currentPacketFlags.get(TCPFlag.ACK)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_RECEIVED);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_RECEIVED);
          return ConnectionStatus.SYN_RECEIVED;
        }
      }
      case SYN_SENT -> {
        LOGGER.debug("SYN SENT");
        if (currentPacketFlags.get(TCPFlag.SYN)
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_RECEIVED);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_RECEIVED);
          return ConnectionStatus.SYN_RECEIVED;
        } else if (currentPacketFlags.get(TCPFlag.SYN)) {
          // simultaneous open
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_RECEIVED);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_RECEIVED);
          return ConnectionStatus.SYN_RECEIVED;
        } else if (currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.ESTABLISHED);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.ESTABLISHED);
          return ConnectionStatus.ESTABLISHED;
        }
      }
      case SYN_RECEIVED -> {
        LOGGER.debug("SYN received");
        if (packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.ESTABLISHED);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.ESTABLISHED);

          return ConnectionStatus.ESTABLISHED;
        }
      }
      case ESTABLISHED -> {
        LOGGER.debug("Established");
        if (!pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.CLOSE_WAIT);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.CLOSE_WAIT);
          return ConnectionStatus.CLOSE_WAIT;
        } else if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.FIN_WAIT_1);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.FIN_WAIT_1);
          return ConnectionStatus.FIN_WAIT_1;
        } else if (packetBeingAcked.isPresent() && packetBeingAcked.get().getDataPayloadLength() > 0) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.ESTABLISHED);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.ESTABLISHED);
          return ConnectionStatus.ESTABLISHED;
        }
      }
      case CLOSE_WAIT -> {
        LOGGER.debug("close wait");
        if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.LAST_ACK);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.LAST_ACK);
          return ConnectionStatus.LAST_ACK;
        }
      }
      case LAST_ACK -> {
        LOGGER.debug("last ack");
        if (!pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.CLOSED);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.CLOSED);
          return ConnectionStatus.CLOSED;
        } else if (currentPacketFlags.get(TCPFlag.SYN) && !currentPacketFlags.get(TCPFlag.ACK)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_SENT);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_SENT);
          return ConnectionStatus.SYN_SENT;
        } else if (currentPacketFlags.get(TCPFlag.SYN)
                && currentPacketFlags.get(TCPFlag.ACK)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_RECEIVED);

          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_RECEIVED);
          return ConnectionStatus.SYN_RECEIVED;
        }
      }
      case FIN_WAIT_1 -> {
        LOGGER.debug("fin wait");

        if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)
          && !packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.CLOSING);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.CLOSING);
          return ConnectionStatus.CLOSING;
        } else if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.TIME_WAIT);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.TIME_WAIT);
          return ConnectionStatus.TIME_WAIT;
        } else if (!pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.FIN_WAIT_2);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.FIN_WAIT_2);
          return ConnectionStatus.FIN_WAIT_2;
        }
      }
      case FIN_WAIT_2 -> {
        LOGGER.debug("fin wait 2");
        if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.TIME_WAIT);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.TIME_WAIT);
          return ConnectionStatus.TIME_WAIT;
        }
      }
      case TIME_WAIT -> {
        LOGGER.debug("Time wait");
        tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.CLOSED);
        pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.CLOSED);
      }
      case UNKNOWN -> {
        LOGGER.debug("unknown");
        if (pkt.getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.CLOSED);
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.CLOSED);
          return ConnectionStatus.CLOSED;
        } else if (packetBeingAcked.isPresent() && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)
          && currentPacketFlags.get(TCPFlag.SYN)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_RECEIVED);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_RECEIVED);
          return ConnectionStatus.SYN_RECEIVED;
        } else if (currentPacketFlags.get(TCPFlag.SYN)
          && currentPacketFlags.get(TCPFlag.ACK)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_RECEIVED);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_RECEIVED);
          return ConnectionStatus.SYN_RECEIVED;
        } else if (currentPacketFlags.get(TCPFlag.SYN)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_SENT);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_SENT);
          return ConnectionStatus.SYN_SENT;
        } else if (packetBeingAcked.isPresent()) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.ESTABLISHED);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.ESTABLISHED);
          return ConnectionStatus.ESTABLISHED;
        }
      }
      case REJECTED -> {
        if (pkt.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.SYN)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_RECEIVED);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_RECEIVED);
          return ConnectionStatus.SYN_RECEIVED;
        } else if (currentPacketFlags.get(TCPFlag.SYN)) {
          pkt.setTcpConnectionStatusAsOfPacket(ConnectionStatus.SYN_SENT);
          tcpConnection.setStatusAsOfPacketTraversal(ConnectionStatus.SYN_SENT);
          return ConnectionStatus.SYN_SENT;
        }
      }
    }

    return tcpConnection.getStatusAsOfPacketTraversal();
  }

  /* Generates a string for TCP flags present on the packet
   */
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
      sb.append("SYN");
    }
    if (filtersForm.isShowHeaderFlags() && flags.get(TCPFlag.RST)) {
      if (flagCount > 0) {
        sb.append(", ");
      }
      flagCount++;
      sb.append("RST");
    }

    if (filtersForm.isShowHeaderFlags() && flags.get(TCPFlag.URG)) {
      if (flagCount > 0) {
        sb.append(", ");
      }
      flagCount++;
      sb.append("URG");
    }

    if (filtersForm.isShowAckAndSeqNumbers()) {
      sb.append(" %s ".formatted(pkt.getSequenceNumber()));
    }

    if (filtersForm.isShowHeaderFlags() && flags.get(TCPFlag.FIN)) {
      if (flagCount > 0) {
        sb.append(", ");
      }
      flagCount++;

      sb.append("FIN");
    }

    if (filtersForm.isShowHeaderFlags() && flags.get(TCPFlag.ACK)) {
      if (flagCount > 0) {
        sb.append(", ");
      }
      sb.append("ACK");
    }
    if (filtersForm.isShowAckAndSeqNumbers() && flags.get(TCPFlag.ACK)) {
      sb.append(" %s".formatted(pkt.getAckNumber()));
    }

    if (filtersForm.isShowLength()) {
      sb.append(" Length %s".formatted(pkt.getDataPayloadLength()));
    }

    return sb.toString();
  }

  /* Generates a string for the TCP options present on the packet
   */
  public String getTcpOptionsForPacket(EasyTCPacket pkt, FiltersForm filtersForm) {
    var options = pkt.getTcpOptions();
    var windowSize = pkt.getWindowSize();
    var sb = new StringBuilder();
    if (filtersForm.isShowWindowSize()) {
      sb.append("Win %s\n".formatted(windowSize));
    }
    if (filtersForm.isShowTcpOptions()) {
      sb.append("<");
      options.forEach(opt -> {
        var kind = opt.getKind();
        if (kind.equals(TcpOptionKind.MAXIMUM_SEGMENT_SIZE)) {
          var mss = (TcpMaximumSegmentSizeOption) opt;
          sb.append("MSS %s bytes".formatted(mss.getMaxSegSize()));
        } else if(kind.equals(TcpOptionKind.WINDOW_SCALE)) {
          var ws = (TcpWindowScaleOption) opt;
          sb.append("Window scale %s".formatted(ws.getLength()));
        } else if (!kind.equals(TcpOptionKind.NO_OPERATION)
            && !kind.equals(TcpOptionKind.END_OF_OPTION_LIST)) {
          sb.append(opt.getKind().name());
        }
        sb.append(" ");
      });
      sb.delete(sb.length()-1, sb.length()-1);
      sb.append(">");
    }
    return sb.toString();

  }

  /* Gets a timestamp string relative to the first segment sent/received on the connection.
   */
  public String getConnectionTimestampForPacket(EasyTCPacket pkt) {
    var con = pkt.getTcpConnection();
    var firstPacket = con.getPacketContainer()
      .getPackets().get(0); // earliest packet should be the first packet in the container

    var duration = Duration.between(firstPacket.getTimestamp().toInstant(), pkt.getTimestamp().toInstant());
    var nanos = duration.getSeconds() + (duration.getNano() / 1e+9);

    return "%f (%.04f)".formatted(nanos, nanos);
  }

  /* Gets the segment number for the packet
   */
  public String getSegmentLabel(EasyTCPacket pkt) {
    var con = pkt.getTcpConnection();
    var indexOf = con.getPacketContainer()
      .getPackets()
      .indexOf(pkt);

    return "Segment %s".formatted(indexOf+1);
  }
}
