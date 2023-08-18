package easytcp.service;

import easytcp.model.CaptureStatus;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.EasyTCPacket;
import easytcp.view.OptionsPanel;
import org.pcap4j.core.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

public class PcapFileReaderService {
  private static final Logger LOGGER = LoggerFactory.getLogger(PcapFileReaderService.class);
  private final PacketTransformerService packetTransformerService;
  private final PacketDisplayService packetDisplayService;
  private final CaptureData captureData;

  public PcapFileReaderService(PacketTransformerService packetTransformerService) {
    this.packetTransformerService = packetTransformerService;
    this.packetDisplayService = ServiceProvider.getInstance().getPacketDisplayService();
    this.captureData = CaptureData.getInstance();
  }

  public CaptureData readPacketFile(File packetFile, FiltersForm filtersForm,
                                    JTextPane textPane, OptionsPanel optionsPanel) throws PcapNativeException, NotOpenException {
    PcapHandle handle;
    try {
      handle = Pcaps.openOffline(packetFile.getPath(), PcapHandle.TimestampPrecision.NANO);
    } catch (PcapNativeException e) {
      handle = Pcaps.openOffline(packetFile.getPath());
    }

    var appStatus = ApplicationStatus.getStatus();
    appStatus.setMethodOfCapture(CaptureStatus.READING_FROM_FILE);
    appStatus.setLoading(true);
    captureData.clear();
    var threadPool = Executors.newCachedThreadPool();
    try {
      int maxPackets = Integer.MAX_VALUE;
      handle.setFilter(filtersForm.toBfpExpression(), BpfProgram.BpfCompileMode.OPTIMIZE);
      PcapHandle finalHandle = handle;
      handle.loop(maxPackets, (PacketListener) packet -> {
        var ipPacket = packet.get(IpPacket.class);
        if (ipPacket != null) {
          var tcpPacket = ipPacket.get(TcpPacket.class);
          if (tcpPacket != null) {
            var easyTCPacket = packetTransformerService.fromPackets(
              ipPacket, tcpPacket, finalHandle.getTimestamp(), captureData, filtersForm);
            captureData.getPackets().addPacketToContainer(easyTCPacket);
            SwingUtilities.invokeLater(() -> {
              textPane.setText(new ArrayList<>(captureData
                .getPackets().getPackets())
                      .stream()
                      .sorted(Comparator.comparing(EasyTCPacket::getTimestamp))
                      .map(pkt -> packetDisplayService.prettyPrintPacket(pkt, filtersForm))
                      .collect(Collectors.joining("\n")));
              textPane.revalidate();
              textPane.repaint();
//                var styledDocument = textPane.getStyledDocument();
//                try {
//                  styledDocument
//                    .insertString(
//                      styledDocument.getLength(),
//                      "\n" + packetDisplayService.prettyPrintPacket(easyTCPacket, filtersForm), null);
//                } catch (BadLocationException e) {
//                  LOGGER.debug("Text pane error");
//                  throw new RuntimeException(e);
//                }
              //} //else {
//                    textPane.setText(new ArrayList<>(captureData
//                      .getPackets())
//                      .stream()
//                      .sorted(Comparator.comparing(EasyTCPacket::getTimestamp))
//                      .map(pkt -> packetDisplayService.prettyPrintPacket(pkt, filtersForm))
//                      .collect(Collectors.joining("\n")));
            //  }
              optionsPanel.getMiddleRow().setConnectionStatusLabel(this.captureData);
              optionsPanel.getCaptureDescriptionPanel().updateCaptureStats(this.captureData);
            });
          }
        }
      }, threadPool);
    } catch (Exception e) {
      LOGGER.debug(e.getMessage());
      LOGGER.debug("Error sniffing packet");
    } finally {
      threadPool.shutdown();
    }
    handle.close();
    LOGGER.debug("Finished reading file");
    return captureData;
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
