package easytcp.service;

import easytcp.model.CaptureStatus;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.EasyTCPacket;
import easytcp.view.options.OptionsPanel;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

public class LiveCaptureService {
  private static final Logger LOGGER = LoggerFactory.getLogger(LiveCaptureService.class);
  private final static int SNAPSHOT_LENGTH = 65536; // in bytes
  private final CaptureData captureData;
  private final PacketTransformerService packetTransformerService;
  private final PacketDisplayService packetDisplayService;
  private AtomicBoolean isSettingText;

  public LiveCaptureService(ServiceProvider serviceProvider) {
    this.captureData = CaptureData.getInstance();
    this.packetTransformerService = serviceProvider.getPacketTransformerService();
    this.packetDisplayService = serviceProvider.getPacketDisplayService();
  }

  public PcapHandle startCapture(PcapNetworkInterface networkInterface,
                                 FiltersForm filtersForm,
                                 JTextPane textPane,
                                 OptionsPanel optionsPanel) throws PcapNativeException {
    LOGGER.info("Beginning capture on " + networkInterface);
    var appStatus = ApplicationStatus.getStatus();
    appStatus.setLiveCapturing(true);

    appStatus.setMethodOfCapture(CaptureStatus.LIVE_CAPTURE);
    // begin capture
    final PcapHandle handle =
      networkInterface.openLive(SNAPSHOT_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
    LOGGER.debug("Began live capture");
    var executor = Executors.newSingleThreadExecutor();
    this.isSettingText = new AtomicBoolean();
    isSettingText.set(false);
    executor.execute(() -> {
      var threadPool = Executors.newCachedThreadPool();

      try {
        int maxPackets = Integer.MAX_VALUE;
        handle.setFilter(filtersForm.toBfpExpression(), BpfProgram.BpfCompileMode.OPTIMIZE);
        handle.loop(maxPackets, (PacketListener) packet -> {
          var ipPacket = packet.get(IpPacket.class);
          if (ipPacket != null) {
            var tcpPacket = ipPacket.get(TcpPacket.class);
            if (tcpPacket != null) {
              var timestamp = handle.getTimestamp();
              var easyTCPacket = packetTransformerService.fromPackets(
                ipPacket, tcpPacket, timestamp, captureData, filtersForm);
              packetTransformerService.storePcap4jPackets(ipPacket, tcpPacket, timestamp);
              captureData.getPackets().addPacketToContainer(easyTCPacket);
              if (!isSettingText.get()) {
                //ensures the text is being set only once at the same time, preventing the UI from freezing up from constant updates
                isSettingText.set(true);
                SwingUtilities.invokeLater(() -> {
                  setLogTextPane(filtersForm, textPane, captureData, packetDisplayService, optionsPanel);
                  isSettingText.set(false);
                });
              }
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
    executor.shutdown();
    return handle;
  }

  public static void setLogTextPane(FiltersForm filtersForm,
                                    JTextPane textPane,
                                    CaptureData captureData,
                                    PacketDisplayService packetDisplayService,
                                    OptionsPanel optionsPanel) {
    textPane.setText("<html>" + new ArrayList<>(captureData
      .getPackets().getPackets())
      .stream()
      .filter(pkt -> packetDisplayService.isVisible(pkt, filtersForm))
      .sorted(Comparator.comparing(EasyTCPacket::getTimestamp))
      .map(pkt -> packetDisplayService.prettyPrintPacket(pkt, filtersForm))
      .collect(Collectors.joining()) + "</html>");
    textPane.setContentType("text/html");
    textPane.revalidate();
    textPane.repaint();
    optionsPanel.getMiddleRow().setConnectionStatusLabel(captureData);
    optionsPanel.getCaptureDescriptionPanel().updateCaptureStats(captureData);
  }
}
