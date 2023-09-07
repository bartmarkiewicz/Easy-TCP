package easytcp.view;

import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.service.PacketDisplayService;
import easytcp.service.PacketTransformerService;
import easytcp.service.ServiceProvider;
import easytcp.service.capture.LiveCaptureService;
import easytcp.service.capture.PcapFileReaderService;
import easytcp.view.options.MiddleRow;
import easytcp.view.options.OptionsPanel;
import org.apache.logging.log4j.util.Strings;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.text.DefaultCaret;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
import java.awt.*;
import java.io.File;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import static easytcp.service.capture.LiveCaptureService.setLogTextPane;

/*Class for displaying the text based capture log.
 */
public class PacketLog {

  private static final Logger LOGGER = LoggerFactory.getLogger(PacketLog.class);
  private static PacketLog packetLog;
  private final FiltersForm filtersForm;
  private final JTextPane logTextPane;
  private final PcapFileReaderService pcapFileReaderService;
  private final PacketDisplayService packetDisplayService;
  private final LiveCaptureService liveCaptureService;
  private PcapHandle pcapHandle;
  private final CaptureData captureData;
  private final ApplicationStatus appStatus;
  private JScrollPane scrollPane;

  public PacketLog(FiltersForm filtersForm, ServiceProvider serviceProvider) {
    this.filtersForm = filtersForm;
    this.captureData = CaptureData.getInstance();
    this.logTextPane = getTextPane();
    this.appStatus = ApplicationStatus.getStatus();
    this.pcapFileReaderService = serviceProvider.getPcapFileReaderService();
    this.packetDisplayService = serviceProvider.getPacketDisplayService();
    this.liveCaptureService = serviceProvider.getLiveCaptureService();
    packetLog = this;
  }

  /* Reads the selected pcap file
   */
  public void readSelectedFile(File selectedFile, OptionsPanel optionsPanel) {
    if (appStatus.isLoading().get() || appStatus.isLiveCapturing().get()) {
      //Cannot read a file while a file is already being loaded or packets are being live captured.
      LOGGER.debug("Attempted to read a file while live capturing");
      JOptionPane.showMessageDialog(
        optionsPanel.getPanel(), "Error, cannot read file while " +
          "already live capturing packets, please stop the capture first.");
    } else {
      var executor = Executors.newSingleThreadExecutor();
      //runs the file reading on another thread to not hang the Swing UI thread which calls readSelectedFile.
      executor
        .execute(() -> this.pcapFileReaderService.readPacketFile(
          selectedFile, filtersForm, logTextPane, optionsPanel));
      executor.shutdown(); //This ensures the thread is shutdown after the work on it is done, to not hog system resources.
    }
  }

  /* This method begins or stops the live packet capture process.
   */
  public void startPacketCapture(PcapNetworkInterface networkInterface,
                                 OptionsPanel optionsPanel) throws PcapNativeException, NotOpenException {
    if (!appStatus.isLiveCapturing().get() && pcapHandle == null) {
      //checks if currently is capturing, prevents another call to capture
      SwingUtilities.invokeLater(() -> {
        //sets the filters on the ArrowDiagram and repaints it on the UI thread.
        ArrowDiagram.getInstance().setFilters(filtersForm);
        ArrowDiagram.getInstance().repaint();
        ArrowDiagram.getInstance().revalidate();
      });
      this.pcapHandle = liveCaptureService.startCapture(
        networkInterface, filtersForm, logTextPane, optionsPanel);
    } else if (this.pcapHandle != null) {
      // this stops the live capture while its in progress
      pcapHandle.breakLoop();
      pcapHandle.close();
      LOGGER.debug("Stopping live capture");
      ApplicationStatus.getStatus().setLiveCapturing(false);
      //this updates the views one last time after capture has stopped.
      SwingUtilities.invokeLater(() -> {
        setLogTextPane(filtersForm, logTextPane, captureData, packetDisplayService, optionsPanel);
        MiddleRow.getInstance().addConnectionOptions(captureData);
      });
      this.pcapHandle = null;
    }
  }

  /*This restores defaults everywhere and clears the data once the user click file -> new
   */
  public void newLog() {
    captureData.clear();
    PacketTransformerService.getPcapCaptureData().clear();
    if (pcapHandle != null && pcapHandle.isOpen()) {
      try {
        pcapHandle.breakLoop();
      } catch (NotOpenException e) {
        LOGGER.debug(e.getMessage());
      }
      pcapHandle.close();
      pcapHandle = null;
    }
    filtersForm.restoreDefaults();
    SwingUtilities.invokeLater(() -> {
      var middleRow = MiddleRow.getInstance();
      middleRow.resetConnectionInformation();
      middleRow.addConnectionOptions(captureData);
      var arrowDiagram = ArrowDiagram.getInstance();
      arrowDiagram.setTcpConnection(null, filtersForm);
      refilterPackets();
      logTextPane.setText("");
      logTextPane.revalidate();
      logTextPane.repaint();
    });
  }

  /* This handles the filter button click, by re-setting the packet text.
   */
  public void refilterPackets() {
    var packetText = getPacketText();

    SwingUtilities.invokeLater(() -> {
      ArrowDiagram.getInstance().setFilters(filtersForm);
      ArrowDiagram.getInstance().repaint();
      ArrowDiagram.getInstance().revalidate();
      ((DefaultCaret) packetLog.getPacketTextPane().getCaret()).setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
      logTextPane.setContentType("text/html");
      if (Strings.isBlank(packetText)) {
        logTextPane.setText("<html> No packets matching your search criteria found, try changing your filters.</html>");
      } else {
        logTextPane.setText(packetText);
      }
      logTextPane.repaint();
      logTextPane.revalidate();
      ((DefaultCaret) packetLog.getPacketTextPane().getCaret()).setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
    });
  }

  //packet can be null
  public void refreshPacketLog(boolean setViewport) {
    var caret = (DefaultCaret) logTextPane.getCaret();
    var packetText = getPacketText();
    SwingUtilities.invokeLater(() -> {
      caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
      logTextPane.setContentType("text/html");
      if (Strings.isBlank(packetText)) {
        logTextPane.setText("<html> No packets matching your search criteria found, try changing your filters.</html>");
      } else {
        logTextPane.setText(packetText);
      }

      if (setViewport) {
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
        int i = 0;
        //scrolls to the selected packet
        for (String line : logTextPane.getText().split("<p>")) {
          if (!Strings.isBlank(line) && line.contains("<span>")) {
            if (i < 5) {
              scrollPane.getViewport().setViewPosition(new Point(0, 0));
            } else {
              scrollPane.getViewport().setViewPosition(new Point(0, i * 30));
            }
            break;
          }
          i++;
        }
      }
    });
  }

  public CaptureData getCaptureData() {
    return captureData;
  }

  public JTextPane getPacketTextPane() {
    return this.logTextPane;
  }

  /* This returns html text for the packet log after applying the filters.
   */
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

  private void handlePacketClick(HyperlinkEvent e) {
    //if hyperlink is clicked
    if (e.getEventType().equals(HyperlinkEvent.EventType.ACTIVATED)) {
      var url = e.getDescription().split(":"); //the separator between the values in the href
      var sequenceNumber = url[0];
      var payloadLength = url[1];
      var ackNumber = url[2];
      var tcpFlagsDisplayable = url[3];
      var tcpConnectionHostAddress = url[4];

      //extracts the address from the url and looks through the map of tcp connections
      //to find the object for it.
      var addressOpt = this.captureData.getTcpConnectionMap().keySet()
        .stream()
        .filter(addr -> addr.toString().equals(tcpConnectionHostAddress))
        .findFirst();

      if (addressOpt.isPresent()) {
        var tcpConnectionOfPacket = captureData
          .getTcpConnectionMap()
          .get(addressOpt.get());
        //gets the selected packet object from the connection
        var selectedPkt = tcpConnectionOfPacket.getPacketContainer()
          .findPacketWith(
            Long.parseLong(sequenceNumber),
            Long.parseLong(ackNumber),
            Integer.parseInt(payloadLength),
            tcpFlagsDisplayable);
        selectedPkt.ifPresent(packet ->
          //if packet found, updates the arrow diagram and selects the connection on the UI thread
          SwingUtilities.invokeLater(() -> {
            var mr = MiddleRow.getInstance();
            mr.setConnectionInformation(tcpConnectionOfPacket);
            ArrowDiagram.getInstance().setTcpConnection(tcpConnectionOfPacket, filtersForm);
            ArrowDiagram.getInstance().setSelectedPacket(packet, true);
            refreshPacketLog(false);
          }));
      } else {
        var packetOpt = this.captureData.getPackets().findPacketWith(
          Long.valueOf(sequenceNumber), Long.valueOf(ackNumber), Integer.valueOf(payloadLength), tcpFlagsDisplayable);
        packetOpt.ifPresent(packet ->
          //if packet found, updates the arrow diagram and selects the connection on the UI thread
          SwingUtilities.invokeLater(() -> {
            ArrowDiagram.getInstance().setTcpConnection(packet.getTcpConnection(), filtersForm);
            ArrowDiagram.getInstance().setSelectedPacket(packet, true);
            var mr = MiddleRow.getInstance();
            mr.setConnectionInformation(packetOpt.get().getTcpConnection());
            refreshPacketLog(false);
          }));
      }
    }
  }

  private JTextPane getTextPane() {
    var textPane = new JTextPane();
    textPane.setEditable(false);
    textPane.setContentType("text/html");
    var hed = new HTMLEditorKit();
    var defaultStyle = hed.getStyleSheet();
    var style = new StyleSheet();
    style.addStyleSheet(defaultStyle);
    //adds css to the packet log text
    style.addRule("body {font-family:\"Monospaced\"; font-size:10px;}");
    style.addRule("a {color:#000000; text-decoration: none;}");
    style.addRule("span {color:#0000ff; text-decoration: none;}");
    //Ensures capture log packets are correctly read as html and edits the default hyperlink styling.
    hed.setStyleSheet(style);
    textPane.setEditorKit(hed);
    textPane.setDocument(hed.createDefaultDocument());
    textPane.addHyperlinkListener(this::handlePacketClick);
    return textPane;
  }

  public static PacketLog getPacketLog(FiltersForm filtersForm, ServiceProvider serviceProvider) {
    if (packetLog != null) {
      return packetLog;
    } else {
      packetLog = new PacketLog(filtersForm, serviceProvider);
    }
    return packetLog;
  }

  public void setScrollPane(JScrollPane packetViewScroll) {
    this.scrollPane = packetViewScroll;
  }
}
