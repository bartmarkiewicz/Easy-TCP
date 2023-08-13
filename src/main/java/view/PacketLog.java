package view;

import model.CaptureData;
import model.FiltersForm;
import org.apache.logging.log4j.util.Strings;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import service.LiveCaptureService;
import service.PacketDisplayService;
import service.PcapFileReaderService;
import service.ServiceProvider;

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

  public PacketLog(FiltersForm filtersForm) {
    this.filtersForm = filtersForm;
    this.logTextPane = new JTextPane();
    logTextPane.setEditable(false);
    this.captureData = new CaptureData();
    this.pcapFileReaderService = ServiceProvider.getPcapFileReaderService();
    this.packetDisplayService = ServiceProvider.getPacketDisplayService();
    this.liveCaptureService = ServiceProvider.getLiveCaptureService();
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
    if (pcapHandle == null) {
      this.pcapHandle = liveCaptureService.startCapture(
        networkInterface, filtersForm, logTextPane, captureDescriptionPanel);
    } else if (stopCapture) {
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
