package easytcp.service.capture;

import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.service.PacketDisplayService;
import easytcp.service.PacketTransformerService;
import easytcp.view.ArrowDiagram;
import easytcp.view.options.OptionsPanel;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.util.concurrent.atomic.AtomicBoolean;

import static easytcp.service.capture.LiveCaptureService.setLogTextPane;

//Listener which handles a packet arriving at an interface when live capturing
public class LivePacketListener implements PacketListener {
  private static final Logger LOGGER = LoggerFactory.getLogger(LivePacketListener.class);
  private final PcapHandle handle;
  private final PacketTransformerService packetTransformerService;
  private final CaptureData captureData;
  private final FiltersForm filtersForm;
  private final AtomicBoolean isSettingForm;
  private final JTextPane textPane;
  private final PacketDisplayService packetDisplayService;
  private final OptionsPanel optionsPanel;

  public LivePacketListener(
    PcapHandle handle, PacketTransformerService packetTransformerService,
    CaptureData captureData, FiltersForm filtersForm,
    AtomicBoolean isSettingForm, JTextPane textPane, PacketDisplayService packetDisplayService, OptionsPanel optionsPanel) {
    this.handle = handle;
    this.packetTransformerService = packetTransformerService;
    this.captureData = captureData;
    this.filtersForm = filtersForm;
    this.isSettingForm = isSettingForm;
    this.textPane = textPane;
    this.packetDisplayService = packetDisplayService;
    this.optionsPanel = optionsPanel;
  }

  @Override
  public void gotPacket(Packet packet) {
    //extracts IP and TCP information from the raw packet.
    var ipPacket = packet.get(IpPacket.class);
    if (ipPacket != null) {
      var tcpPacket = ipPacket.get(TcpPacket.class);
      if (tcpPacket != null) {
        var timestamp = handle.getTimestamp();
        //transforms the pcap4j library packets
        var easyTCPacket = packetTransformerService.fromPackets(
          ipPacket, tcpPacket, timestamp, captureData, filtersForm);
        //stores the packets in their pcap4j format - allowing for later saving if needed.
        packetTransformerService.storePcap4jPackets(ipPacket, tcpPacket, timestamp);
        //Adds transformed packet to a container
        captureData.getPackets().addPacketToContainer(easyTCPacket);
        if (!isSettingForm.get()) {
          //ensures the text is being set only once at the same time, preventing the UI from freezing up from constant updates
          isSettingForm.set(true);
          //invoked on the swing UI thread
          SwingUtilities.invokeLater(() -> {
            setLogTextPane(filtersForm, textPane, captureData, packetDisplayService, optionsPanel);
            var arrowDiagram = ArrowDiagram.getInstance();
            if (arrowDiagram.getSelectedConnection() != null
                    && arrowDiagram.getSelectedConnection().equals(easyTCPacket.getTcpConnection())) {
              //update diagram if a packet is added to the selected connection.
              ArrowDiagram.getInstance().repaint();
              ArrowDiagram.getInstance().revalidate();
            }
            isSettingForm.set(false);
          });
        }
      }
    }
    if(!ApplicationStatus.getStatus().isLiveCapturing().get()) {
      LOGGER.debug("Stopping live capture forcefully");
      try {
        handle.breakLoop();
      } catch (NotOpenException e) {
        LOGGER.error(e.getMessage());
      }
      handle.close();
    }
  }
}
