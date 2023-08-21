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
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
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
    this.captureData = CaptureData.getInstance();
    logTextPane.setEditable(false);
    logTextPane.setContentType("text/html");
    var hed = new HTMLEditorKit();
    var defaultStyle = hed.getStyleSheet();
    var style = new StyleSheet();
    style.addStyleSheet(defaultStyle);
    style.addRule("body {font-family:\"Monospaced\"; font-size:9px;}");
    style.addRule("a {color:#000000; text-decoration: none;}");
    hed.setStyleSheet(style);
    logTextPane.setEditorKit(hed);
    logTextPane.setDocument(hed.createDefaultDocument());
    logTextPane.addHyperlinkListener(e -> {
      if(e.getEventType().equals(HyperlinkEvent.EventType.ACTIVATED)) {
        var url = e.getDescription().split(":");
        var sequenceNumber = url[0];
        var payloadLength = url[1];
        var ackNumber = url[2];
        var tcpFlagsDisplayable = url[3];
        var tcpConnectionHostAddress = url[4];
        var addressOpt = this.captureData.getTcpConnectionMap().keySet()
          .stream()
          .filter(addr -> addr.toString().equals(tcpConnectionHostAddress))
          .findFirst();
        if (addressOpt.isPresent()) {
          var tcpConnectionOfPacket = captureData
            .getTcpConnectionMap()
            .get(addressOpt.get());
          var selectedPkt = tcpConnectionOfPacket.getPacketContainer()
            .findPacketWith(
              Long.parseLong(sequenceNumber),
              Long.parseLong(ackNumber),
              Integer.parseInt(payloadLength),
              tcpFlagsDisplayable);
          selectedPkt.ifPresent(packet ->
            SwingUtilities.invokeLater(() -> {
              ArrowDiagram.getInstance().setTcpConnection(tcpConnectionOfPacket, filtersForm);
              ArrowDiagram.getInstance().setSelectedPacket(packet);
              filtersForm.setSelectedConnection(tcpConnectionOfPacket);
              var mr = MiddleRow.getInstance();
              mr.setConnectionSelector(tcpConnectionOfPacket);
              mr.setConnectionInformation(tcpConnectionOfPacket);
          }));
        }
      }
    });
    this.appStatus = ApplicationStatus.getStatus();
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
      var executor = Executors.newSingleThreadExecutor();
      executor
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
      executor.shutdown();
    }
  }

  public void startPacketCapture(PcapNetworkInterface networkInterface,
                                 OptionsPanel optionsPanel) throws PcapNativeException, NotOpenException {
    var appStatus = ApplicationStatus.getStatus();
    if (!appStatus.isLiveCapturing().get() && pcapHandle == null) {
      SwingUtilities.invokeLater(() -> {
        ArrowDiagram.getInstance().setFilters(filtersForm);
        ArrowDiagram.getInstance().repaint();
      });
      this.pcapHandle = liveCaptureService.startCapture(
        networkInterface, filtersForm, logTextPane, optionsPanel);
      MiddleRow.getInstance().resetConnectionInformation();
      MiddleRow.getInstance().addConnectionOptions(captureData);
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
    SwingUtilities.invokeLater(() -> {
      var middleRow = MiddleRow.getInstance();
      middleRow.resetConnectionInformation();
      var arrowDiagram = ArrowDiagram.getInstance();
      arrowDiagram.setTcpConnection(null, filtersForm);
      arrowDiagram.repaint();
      logTextPane.setText("");
      logTextPane.revalidate();
      logTextPane.repaint();
    });
  }

  public void refilterPackets() {
    var packetText = getPacketText();

    SwingUtilities.invokeLater(() -> {
      ArrowDiagram.getInstance().setFilters(filtersForm);
      ArrowDiagram.getInstance().repaint();
      logTextPane.setContentType("text/html");
      if (Strings.isBlank(packetText)) {
        logTextPane.setText("<html> No packets matching your search criteria found, try changing your filters.</html>");
      } else {
        logTextPane.setText(packetText);
      }
      logTextPane.repaint();
      logTextPane.revalidate();
    });
  }

  public CaptureData getCaptureData() {
    return captureData;
  }

  public JTextPane getPacketTextPane() {
    return this.logTextPane;
  }

  private String getPacketText() {
    var sb = new StringBuilder();
    sb.append("<html>");

    sb.append(captureData.getPackets().getPackets()
      .stream()
      .filter(packet -> packetDisplayService.isVisible(packet, filtersForm))
      .map(packet -> packetDisplayService.prettyPrintPacket(packet, filtersForm))
      .collect(Collectors.joining()));
    sb.append("</html>");
    return sb.toString();
  }
}
