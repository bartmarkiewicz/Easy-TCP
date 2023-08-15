package easytcp.view;

import easytcp.model.CaptureData;
import easytcp.model.FiltersForm;
import org.apache.logging.log4j.util.Strings;
import org.pcap4j.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import easytcp.service.LiveCaptureService;
import easytcp.service.PacketDisplayService;
import easytcp.service.PcapFileReaderService;
import easytcp.service.ServiceProvider;

import javax.swing.*;
import java.io.File;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class PacketLog {

  private static final Logger LOGGER = LoggerFactory.getLogger(PacketLog.class);
  private final FiltersForm filtersForm;
  private final JTextPane logTextPane;
  private final PcapFileReaderService pcapFileReaderService;
  private final PacketDisplayService packetDisplayService;
  private final LiveCaptureService liveCaptureService;
  private PcapHandle pcapHandle;
  private CaptureData captureData;

  public PacketLog(FiltersForm filtersForm, ServiceProvider serviceProvider) {
    this.filtersForm = filtersForm;
    this.logTextPane = new JTextPane();
    logTextPane.setEditable(false);
    this.captureData = CaptureData.getInstance();
    this.pcapFileReaderService = serviceProvider.getPcapFileReaderService();
    this.packetDisplayService = serviceProvider.getPacketDisplayService();
    this.liveCaptureService = serviceProvider.getLiveCaptureService();
  }

  public void readSelectedFile(File selectedFile, CaptureDescriptionPanel captureDescriptionPanel) throws PcapNativeException, NotOpenException, ExecutionException, InterruptedException {
    this.captureData = Executors.newSingleThreadExecutor()
      .submit(() -> {
        try {
          return this.pcapFileReaderService.readPacketFile(selectedFile, filtersForm);
        } catch (PcapNativeException e) {
          throw new RuntimeException(e);
        } catch (NotOpenException e) {
          throw new RuntimeException(e);
        }
    }).get();

    logTextPane.setText(getPacketText());
    captureDescriptionPanel.updateCaptureStats(this.captureData);
  }

  public void startPacketCapture(PcapNetworkInterface networkInterface,
                                 boolean stopCapture,
                                 CaptureDescriptionPanel captureDescriptionPanel) throws PcapNativeException, NotOpenException {
    if (pcapHandle == null && !stopCapture) {
      this.pcapHandle = liveCaptureService.startCapture(
        networkInterface, filtersForm, logTextPane, captureDescriptionPanel);
    } else if (stopCapture && this.pcapHandle != null) {
      pcapHandle.breakLoop();
      pcapHandle.close();
      System.out.println("Stopping live capture");
      this.pcapHandle = null;
    }
  }

  public void newLog() {
    captureData.clear();
    SwingUtilities.invokeLater(() -> {
      logTextPane.setText("");
      logTextPane.revalidate();
      logTextPane.repaint();
    });
  }

  public void refilterPackets() {
    var packetText = getPacketText();
    if (Strings.isBlank(packetText)) {
      logTextPane.setText("No packets matching your search criteria found, try changing your filters.");
    } else {
      logTextPane.setText(packetText);
    }
    logTextPane.repaint();
    logTextPane.revalidate();
  }

  public CaptureData getCaptureData() {
    return captureData;
  }

  public JTextPane getPacketTextPane() {
    return this.logTextPane;
  }

  private String getPacketText() {
    return captureData.getPackets()
      .stream()
      .filter(packet -> packetDisplayService.isVisible(packet, filtersForm))
      .map(packet -> packetDisplayService.prettyPrintPacket(packet, filtersForm) + "\n")
      .collect(Collectors.joining("\n"));
  }
}
