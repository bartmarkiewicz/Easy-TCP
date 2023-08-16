package easytcp.service;

import easytcp.model.CaptureStatus;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.view.CaptureDescriptionPanel;
import easytcp.view.MiddleRow;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import java.util.concurrent.Executors;

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
                                 MiddleRow middleRow,
                                 CaptureDescriptionPanel captureDescriptionPanel) throws PcapNativeException {
    LOGGER.info("Beginning capture on " + networkInterface);
    var appStatus = ApplicationStatus.getStatus();
    appStatus.setLiveCapturing(true);
    appStatus.setMethodOfCapture(CaptureStatus.LIVE_CAPTURE);
    captureData.clear();
    // begin capture
    final PcapHandle handle =
      networkInterface.openLive(SNAPSHOT_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
    LOGGER.debug("Began live capture");
    Executors.newSingleThreadExecutor().execute(() -> {
      var threadPool = Executors.newCachedThreadPool();
      try {
        int maxPackets = Integer.MAX_VALUE;
        handle.setFilter(filtersForm.toBfpExpression(), BpfProgram.BpfCompileMode.OPTIMIZE);
        handle.loop(maxPackets, (PacketListener) packet -> {
          var ipPacket = packet.get(IpPacket.class);
          if (ipPacket != null) {
            var tcpPacket = ipPacket.get(TcpPacket.class);
            if (tcpPacket != null) {
              var easyTCPacket = packetTransformerService.fromPackets(
                ipPacket, tcpPacket, handle.getTimestamp(), captureData, filtersForm);
              captureData.getPackets().addPacketToContainer(easyTCPacket);
              SwingUtilities.invokeLater(() -> {
                  var styledDocument = textPane.getStyledDocument();
                  try {
                    styledDocument
                      .insertString(
                        styledDocument.getLength(),
                        packetDisplayService.prettyPrintPacket(easyTCPacket, filtersForm), null);
                  } catch (BadLocationException e) {
                    LOGGER.debug("Text pane error");
                    throw new RuntimeException(e);
                  }
                middleRow.setConnectionStatusLabel(this.captureData);
                captureDescriptionPanel.updateCaptureStats(this.captureData);
              });
            }
          }
          if(!appStatus.isLiveCapturing().get()) {
            LOGGER.debug("Stopping live capture forcefully");
            try {
              handle.breakLoop();
            } catch (NotOpenException e) {
              LOGGER.error(e.getMessage());
            }
            handle.close();
          }
        }, threadPool);
      } catch (Exception e) {
        LOGGER.debug(e.getMessage());
        LOGGER.debug("Error sniffing packet");
      } finally {
        threadPool.shutdown();
      }
    });
    return handle;
  }
}
