package easytcp.service;

import easytcp.model.CaptureData;
import easytcp.model.EasyTCPacket;
import easytcp.model.FiltersForm;
import easytcp.view.CaptureDescriptionPanel;
import org.apache.logging.log4j.util.Strings;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import java.util.Comparator;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class LiveCaptureService {
  private static final Logger LOGGER = LoggerFactory.getLogger(LiveCaptureService.class);
  private final static int SNAPSHOT_LENGTH = 65536; // in bytes
  private final CaptureData captureData;
  private final PacketTransformerService packetTransformerService;
  private final PacketDisplayService packetDisplayService;

  public LiveCaptureService(ServiceProvider serviceProvider) {
    this.captureData = CaptureData.getInstance();
    this.packetTransformerService = serviceProvider.getPacketTransformerService();
    this.packetDisplayService = serviceProvider.getPacketDisplayService();
  }

  public PcapHandle startCapture(PcapNetworkInterface networkInterface,
                                 FiltersForm filtersForm,
                                 JTextPane textPane,
                                 CaptureDescriptionPanel captureDescriptionPanel) throws PcapNativeException {
    LOGGER.info("Beginning capture on " + networkInterface);

    captureData.clear();
    // begin capture
    final PcapHandle handle =
      networkInterface.openLive(SNAPSHOT_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
    LOGGER.debug("Began live capture");
    Executors.newSingleThreadExecutor().execute(() -> {
      try {
        int maxPackets = Integer.MAX_VALUE;
        setFilters(handle, filtersForm);
        var threadPool = Executors.newCachedThreadPool();
        handle.loop(maxPackets, (PacketListener) packet -> {
          var ipPacket = packet.get(IpPacket.class);
          if (ipPacket != null) {
            var tcpPacket = ipPacket.get(TcpPacket.class);
            if (tcpPacket != null) {
              var easyTCPacket = packetTransformerService.fromPackets(
                ipPacket, tcpPacket, handle.getTimestamp(), captureData, filtersForm);
              captureData.getPackets().add(easyTCPacket);
              SwingUtilities.invokeLater(() -> {
                if (captureData.getPackets().get(captureData.getPackets().size()-1).getTimestamp().getTime()
                  < easyTCPacket.getTimestamp().getTime()) {
                  var styledDocument = textPane.getStyledDocument();
                  try {
                    styledDocument
                      .insertString(
                        styledDocument.getLength(),
                        "\n" + packetDisplayService.prettyPrintPacket(easyTCPacket, filtersForm), null);
                  } catch (BadLocationException e) {
                    LOGGER.debug("Text pane error");
                    throw new RuntimeException(e);
                  }
                } else {
                  textPane.setText(captureData
                    .getPackets()
                    .stream()
                    .sorted(Comparator.comparing(EasyTCPacket::getTimestamp))
                    .map(pkt -> packetDisplayService.prettyPrintPacket(pkt, filtersForm))
                    .collect(Collectors.joining("\n")));
                }
                captureDescriptionPanel.updateCaptureStats(this.captureData);
              });
            }
          }
        }, threadPool);
        threadPool.shutdown();
      } catch (Exception e) {
        LOGGER.debug(e.getMessage());
        LOGGER.debug("Error sniffing packet");
      }
    });
    //    setCaptureStats();
    return handle;
  }

  private void setFilters(PcapHandle handle, FiltersForm filtersForm) throws NotOpenException, PcapNativeException {
    var filterBuilder = new StringBuilder();
    filterBuilder.append("(tcp");
    if (filtersForm.isShowIpv4() && filtersForm.isShowIpv6()) {
      filterBuilder.append(" and (ip or ip6))");
    } else if (filtersForm.isShowIpv6()) {
      filterBuilder.append(" and ip6)");
    } else if (filtersForm.isShowIpv4()) {
      filterBuilder.append(" and ip)");
    } else {
      filterBuilder.append(")");
    }
    if (!Strings.isBlank(filtersForm.getHostSelected())) {
      filterBuilder.append(" and (host %s)"
        .formatted(filtersForm.getHostSelected().replace(" ", "")));
    }
    if (!Strings.isBlank(filtersForm.getPortRangeSelected())) {
      var temp = filtersForm.getPortRangeSelected().replace(" ", "");
      if (temp.contains("-")) {
        filterBuilder.append(" and (portrange %s)".formatted(temp));
      } else {
        filterBuilder.append(" and (port %s)".formatted(temp));
      }
    }
//    and (port <specific_port>)

    handle.setFilter(filterBuilder.toString(), BpfProgram.BpfCompileMode.OPTIMIZE);

//

//
//    if (!Strings.isBlank(filtersForm.getPortRangeSelected())) {
//      var temp = filtersForm.getPortRangeSelected().replace(" ", "");
//      if (temp.contains("-")) {
//        handle.setFilter("dst portrange %s".formatted(temp), BpfProgram.BpfCompileMode.OPTIMIZE);
//      } else {
//        handle.setFilter("dst port %s".formatted(temp), BpfProgram.BpfCompileMode.OPTIMIZE);
//      }
//    }
  }

//  private void setCaptureStats() {
//    this.captureData.setTcpConnectionsEstablished(captureData.getPackets()
//      .stream()
//      .filter(i -> i.getTcpFlags().get(TCPFlag.SYN))
//      .map(i -> i.getDestinationAddress().getAlphanumericalAddress())
//      .distinct()
//      .count());
//  }
}
