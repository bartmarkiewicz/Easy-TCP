package easytcp.service;

import easytcp.model.CaptureData;
import easytcp.model.FiltersForm;
import easytcp.model.TCPFlag;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import easytcp.view.CaptureDescriptionPanel;

import javax.swing.*;
import javax.swing.text.BadLocationException;

public class LiveCaptureService {
  private static final Logger LOGGER = LoggerFactory.getLogger(LiveCaptureService.class);
  private final static int SNAPSHOT_LENGTH = 65536; // in bytes
  private final static int READ_TIMEOUT = Integer.MAX_VALUE;
  private final CaptureData captureData;
  private final PacketTransformerService packetTransformerService;
  private final PacketDisplayService packetDisplayService;

  public LiveCaptureService(ServiceProvider serviceProvider) {
    this.captureData = new CaptureData();
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
      networkInterface.openLive(SNAPSHOT_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

    try {
      int maxPackets = Integer.MAX_VALUE;
      handle.setFilter(filtersForm.toBfpExpression(), BpfProgram.BpfCompileMode.OPTIMIZE);
      handle.loop(maxPackets, (PacketListener) packet -> {
          var ipPacket = packet.get(IpPacket.class);
          if (ipPacket != null) {
            var tcpPacket = ipPacket.get(TcpPacket.class);
            if (tcpPacket != null) {
              var easyTCPacket = packetTransformerService.fromPackets(
                ipPacket, tcpPacket, handle.getTimestamp(), captureData.getResolvedHostnames(), filtersForm);
              captureData.getPackets().add(easyTCPacket);
                SwingUtilities.invokeLater(() -> {
                  try {
                    var styledDocument = textPane.getStyledDocument();
                    styledDocument
                      .insertString(
                        styledDocument.getLength(),
                    "\n" + packetDisplayService.prettyPrintPacket(easyTCPacket, filtersForm), null);
                    captureDescriptionPanel.updateCaptureStats(this.captureData);
                  } catch (BadLocationException e) {
                    LOGGER.debug(e.getMessage());
                    LOGGER.debug("Error updating document");
                    throw new RuntimeException(e);
                  }
                });
            }
          }
      });
    } catch (Exception e) {
      LOGGER.debug(e.getMessage());
      LOGGER.debug("Error sniffing packet");
    }
    LOGGER.debug("ended capture");
    setCaptureStats();

    return handle;
  }

  private void setCaptureStats() {
    this.captureData.setTcpConnectionsEstablished(captureData.getPackets()
      .stream()
      .filter(i -> i.getTcpFlags().get(TCPFlag.SYN))
      .map(i -> i.getDestinationAddress().getAlphanumericalAddress())
      .distinct()
      .count());
  }
}
