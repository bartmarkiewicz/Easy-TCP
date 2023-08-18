package easytcp.service;

import easytcp.model.TCPFlag;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.EasyTCPacket;
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

  public String getDiagramLabelForPacket(EasyTCPacket pkt) {
    var connection = pkt.getTcpConnection();
    var packets = connection.getPacketContainer();
    if (pkt.getTcpFlags().get(TCPFlag.ACK)) {
      // if ack packet
      var ackedPacketOpt = packets.findPacketWithSeqNumber(pkt.getAckNumber());
      if (ackedPacketOpt.isPresent()) {
        var ackedPacket = ackedPacketOpt.get();
        if (ackedPacket.getTcpFlags().get(TCPFlag.PSH)) {
          return ConnectionStatus.ESTABLISHED.getDisplayText();
        } else if (ackedPacket.getTcpFlags().get(TCPFlag.FIN)) {
          return ConnectionStatus.FIN_WAIT_2.getDisplayText();
        }
      }
    }
    return "Fish";
  }
}
