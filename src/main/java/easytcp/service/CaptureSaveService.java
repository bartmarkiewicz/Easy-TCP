package easytcp.service;

import easytcp.model.PcapCaptureData;
import easytcp.view.ArrowDiagram;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CaptureSaveService {
  private static final Logger LOGGER = LoggerFactory.getLogger(CaptureSaveService.class);
  private PacketTransformerService packetTransformerService;

  public CaptureSaveService() {
    this.packetTransformerService = ServiceProvider.getInstance().getPacketTransformerService();
  }

  public void saveArrowDiagram(String fileName) {
    ArrowDiagram.getInstance().saveDiagram(fileName);
  }

  public void saveCapture(String fileName) {
    var capturedPackets = PacketTransformerService.getPcapCaptureData();

    try (var handleOpened = Pcaps.openDead(DataLinkType.IEEE802, Integer.MAX_VALUE);
         var dumper = handleOpened.dumpOpen(fileName + ".pcap")) {
      for (PcapCaptureData pcapData : capturedPackets) {
        dumper.dump(pcapData.ipPacket());
        dumper.dump(pcapData.tcpPacket());
      }
    } catch (Exception e) {
      LOGGER.debug("Error saving file");
    }
  }
}
