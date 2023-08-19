package easytcp.view;

import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.service.LiveCaptureService;
import easytcp.service.PacketDisplayService;
import easytcp.service.PcapFileReaderService;
import easytcp.service.ServiceProvider;
import org.apache.logging.log4j.util.Strings;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
  private final ApplicationStatus appStatus;

  public PacketLog(FiltersForm filtersForm, ServiceProvider serviceProvider) {
    this.filtersForm = filtersForm;
    this.logTextPane = new JTextPane();
    logTextPane.setEditable(false);
    this.appStatus = ApplicationStatus.getStatus();
    this.captureData = CaptureData.getInstance();
    this.pcapFileReaderService = serviceProvider.getPcapFileReaderService();
    this.packetDisplayService = serviceProvider.getPacketDisplayService();
    this.liveCaptureService = serviceProvider.getLiveCaptureService();
  }

  public void readSelectedFile(File selectedFile, OptionsPanel optionsPanel) throws PcapNativeException, NotOpenException, ExecutionException, InterruptedException {
    if (appStatus.isLoading().get() || appStatus.isLiveCapturing().get()) {
      LOGGER.debug("Attempted to read a file while live capturing");
      JOptionPane.showMessageDialog(
        optionsPanel.getPanel(), "Error, cannot read file while " +
          "already live capturing packets, please stop the capture first.");
    } else {
      Executors.newSingleThreadExecutor()
        .execute(() -> {
          try {
            this.pcapFileReaderService.readPacketFile(
              selectedFile, filtersForm, logTextPane, optionsPanel);
            appStatus.setLoading(false);
          } catch (PcapNativeException e) {
            throw new RuntimeException(e);
          } catch (NotOpenException e) {
            throw new RuntimeException(e);
          }
        });
    }
  }

  public void startPacketCapture(PcapNetworkInterface networkInterface,
                                 MiddleRow middleRow,
                                 CaptureDescriptionPanel captureDescriptionPanel) throws PcapNativeException, NotOpenException {
    var appStatus = ApplicationStatus.getStatus();
    if (!appStatus.isLiveCapturing().get() && pcapHandle == null) {
      ArrowDiagram.getInstance().setFilters(filtersForm);
      ArrowDiagram.getInstance().repaint();
      this.pcapHandle = liveCaptureService.startCapture(
        networkInterface, filtersForm, logTextPane, middleRow, captureDescriptionPanel);
    } else if (this.pcapHandle != null) {
      pcapHandle.breakLoop();
      pcapHandle.close();
      System.out.println("Stopping live capture");
      ApplicationStatus.getStatus().setLiveCapturing(false);
      this.pcapHandle = null;
    }
  }

  public void newLog() {
    captureData.clear();
    if (pcapHandle != null && pcapHandle.isOpen()) {
      try {
        pcapHandle.breakLoop();
      } catch (NotOpenException e) {
        LOGGER.debug(e.getMessage());
        throw new RuntimeException(e);
      }
      pcapHandle.close();
    }
    filtersForm.restoreDefaults();
    var arrowDiagram = ArrowDiagram.getInstance();
    arrowDiagram.setTcpConnection(null, filtersForm);
    arrowDiagram.repaint();
    SwingUtilities.invokeLater(() -> {
      logTextPane.setText("");
      logTextPane.revalidate();
      logTextPane.repaint();
    });
  }

  public void refilterPackets() {
    var packetText = getPacketText();
    ArrowDiagram.getInstance().setFilters(filtersForm);
    ArrowDiagram.getInstance().repaint();
    ArrowDiagram.getInstance().revalidate();
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
    return captureData.getPackets().getPackets()
      .stream()
      .filter(packet -> packetDisplayService.isVisible(packet, filtersForm))
      .map(packet -> packetDisplayService.prettyPrintPacket(packet, filtersForm) + "\n")
      .collect(Collectors.joining("\n"));
  }
}
