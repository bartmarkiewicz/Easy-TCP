package easytcp.service.capture;

import easytcp.model.CaptureStatus;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.EasyTCPacket;
import easytcp.service.PacketDisplayService;
import easytcp.service.PacketTransformerService;
import easytcp.service.ServiceProvider;
import easytcp.view.options.OptionsPanel;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

/* This service is used for live capturing packets
 */
public class LiveCaptureService {
  private static final Logger LOGGER = LoggerFactory.getLogger(LiveCaptureService.class);
  private final static int SNAPSHOT_LENGTH = 65536;
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
    // creates capture handle object on the selected interface
    final PcapHandle handle =
      networkInterface.openLive(SNAPSHOT_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
    LOGGER.debug("Began live capture");
    //begins the capture on another thread
    var executor = Executors.newSingleThreadExecutor();
    this.isSettingText = new AtomicBoolean();
    isSettingText.set(false);
    executor.execute(() -> {
      //each packet captured is handled on a separate thread from the cached thread pool
      var threadPool = Executors.newCachedThreadPool();
      try {
        int maxPackets = Integer.MAX_VALUE;
        //sets the filters on the handle object itself by converting the form to a Bfp expression - so only packets matching the filters will be captured
        handle.setFilter(filtersForm.toBfpExpression(), BpfProgram.BpfCompileMode.OPTIMIZE);
        handle.loop(maxPackets, new LivePacketListener(handle, packetTransformerService, captureData,
          filtersForm, isSettingText, textPane, packetDisplayService, optionsPanel), threadPool);
      } catch (Exception e) {
        LOGGER.debug(e.getMessage());
        LOGGER.debug("Error sniffing packet");
      } finally {
        //makes sure the threadpool is shutdown after the work is done so resources can be released
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
    //sets the packet log text pane, in html format due to the packet hyperlinks
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
    //updates other text based displays
    optionsPanel.getMiddleRow().setConnectionStatusLabel(captureData);
    optionsPanel.getCaptureDescriptionPanel().updateCaptureStats(captureData);
  }
}
