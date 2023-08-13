package service;

import model.CaptureData;
import model.FiltersForm;
import model.TCPFlag;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.File;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;

public class PcapFileReaderService {
  private static final Logger LOGGER = LoggerFactory.getLogger(PcapFileReaderService.class);
  private static final ConcurrentHashMap<String, String> resolvedHostNames = new ConcurrentHashMap<>();

  private final PacketTransformerService packetTransformerService;
  private final CaptureData captureData;

  public PcapFileReaderService(PacketTransformerService packetTransformerService) {
    this.packetTransformerService = packetTransformerService;
    this.captureData = new CaptureData();
  }

  public CaptureData readPacketFile(File packetFile, FiltersForm filtersForm) throws PcapNativeException, NotOpenException {
    PcapHandle handle;
    try {
      handle = Pcaps.openOffline(packetFile.getPath(), PcapHandle.TimestampPrecision.NANO);
    } catch (PcapNativeException e) {
      handle = Pcaps.openOffline(packetFile.getPath());
    }
    LOGGER.debug("File successfully read");
    captureData.clear();

    while(true) {
      try {
        //look into transport layer packets
        var packet = handle.getNextPacketEx();
        var ipPacket = packet.get(IpPacket.class);
        var tcpPacket = ipPacket.get(TcpPacket.class);
        var easyTCPacket = packetTransformerService.fromPackets(
          ipPacket, tcpPacket, handle.getTimestamp(), captureData.getResolvedHostnames(), filtersForm);
        captureData.getPackets().add(easyTCPacket);
      } catch (TimeoutException e) {
        LOGGER.debug("Timeout");
      } catch (EOFException e) {
        LOGGER.debug("EOF");
        break;
      }
    }
    setCaptureStats();
    handle.close();
    return captureData;
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
