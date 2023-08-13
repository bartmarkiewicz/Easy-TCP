package service;

import model.CaptureData;
import model.FiltersForm;
import model.TCPFlag;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import view.CaptureDescriptionPanel;

import javax.swing.*;
import javax.swing.text.BadLocationException;

public class LiveCaptureService {
  private final CaptureData captureData;
  private final PacketTransformerService packetTransformerService;
  private final PacketDisplayService packetDisplayService;
  public LiveCaptureService() {
    this.captureData = new CaptureData();
    this.packetTransformerService = ServiceProvider.getPacketTransformerService();
    this.packetDisplayService = ServiceProvider.getPacketDisplayService();
  }

  public PcapHandle startCapture(PcapNetworkInterface networkInterface,
                                 FiltersForm filtersForm,
                                 JTextPane textPane,
                                 CaptureDescriptionPanel captureDescriptionPanel) throws PcapNativeException {
    System.out.println("Beginning capture on " + networkInterface);
    captureData.clear();
    int snapshotLength = 65536; // in bytes
    int readTimeout = Integer.MAX_VALUE; // ensures it never times out
    // begin capture
    final PcapHandle handle =
      networkInterface.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, readTimeout);

    try {
      int maxPackets = Integer.MAX_VALUE;
      handle.loop(maxPackets, (PacketListener) packet -> {
          var ipPacket = packet.get(IpPacket.class);
          if (ipPacket != null) {
            var tcpPacket = ipPacket.get(TcpPacket.class);
            if (tcpPacket != null) {
              var easyTCPacket = packetTransformerService.fromPackets(
                ipPacket, tcpPacket, handle.getTimestamp(), captureData.getResolvedHostnames(), filtersForm);
              captureData.getPackets().add(easyTCPacket);
//              try {
                SwingUtilities.invokeLater(() -> {
                  try {
                    var styledDocument = textPane.getStyledDocument();
                    styledDocument
                      .insertString(
                        styledDocument.getLength(),
                        "\n" + packetDisplayService.prettyPrintPacket(easyTCPacket, filtersForm), null);
                    captureDescriptionPanel.updateCaptureStats(this.captureData);
                  } catch (BadLocationException e) {
                    e.printStackTrace();
                    throw new RuntimeException(e);
                  }
//
//                  setText(textPane.getText() + "\n" + packetDisplayService.prettyPrintPacket(easyTCPacket, filtersForm));
//                  textPane.revalidate();
//                  textPane.repaint();
                });
//              } catch (InterruptedException e) {
//                throw new RuntimeException(e);
//              } catch (InvocationTargetException e) {
//                throw new RuntimeException(e);
//              }

            }
          }
      });
    } catch (Exception e) {
      e.printStackTrace();
      System.out.println("Error sniffing packet");
    }
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
