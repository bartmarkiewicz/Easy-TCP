package service;

import model.EasyTCPacket;
import model.FiltersForm;

public class PacketDisplayService {

  public boolean isVisible(EasyTCPacket packet, FiltersForm filtersForm) {
    var matchesFilter = true;

    switch (packet.getiPprotocol()) {
      case IPV4 ->
        matchesFilter = filtersForm.isShowIpv4();
      case IPV6 ->
        matchesFilter = filtersForm.isShowIpv6();
    }
    return matchesFilter;
  }

  public String prettyPrintPacket(EasyTCPacket packet, FiltersForm filtersForm) {
    return """
      %s %s %s > %s: Flags [%s], seq %s, ack %s, win %s, options [%s], length %s
      
      """
      .formatted(
        packet.getTimestamp().toString(),
        packet.getiPprotocol().getDisplayName(),
        filtersForm.isResolveHostnames() ? packet.getSourceAddress().getAddressString() : packet.getSourceAddress().getAlphanumericalAddress(),
        filtersForm.isResolveHostnames() ?  packet.getDestinationAddress().getAddressString() : packet.getDestinationAddress().getAlphanumericalAddress(),
        packet.getTcpFlagsDisplayable(),
        packet.getSequenceNumber(),
        packet.getAckNumber(),
        packet.getWindowSize(),
        packet.getTcpOptionsDisplayable(),
        packet.getDataPayloadLength()
      );
  }
}
