package easytcp.service.capture;

import easytcp.model.PcapCaptureData;
import easytcp.service.PacketTransformerService;
import easytcp.view.ArrowDiagram;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.namednumber.DataLinkType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//Service used for saving an image for the arrows diagram or a capture file
public class CaptureSaveService {
  private static final Logger LOGGER = LoggerFactory.getLogger(CaptureSaveService.class);

  public void saveArrowDiagram(String fileName) {
    ArrowDiagram.getInstance().saveDiagram(fileName);
  }

  public void saveCapture(String fileName) {

    var capturedPackets = PacketTransformerService.getPcapCaptureData();
    //opens a raw data link and dumps the packets onto the file specified by fileName.
    try (var handleOpened = Pcaps.openDead(DataLinkType.RAW, Integer.MAX_VALUE);
         var dumper = handleOpened.dumpOpen(fileName)) {
      for (PcapCaptureData pcapData : capturedPackets) {
        dumper.dump(pcapData.ipPacket());
      }
    } catch (Exception e) {
      LOGGER.debug("Error saving file");
    }
  }
}
