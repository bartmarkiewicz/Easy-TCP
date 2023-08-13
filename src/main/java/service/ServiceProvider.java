package service;

public class ServiceProvider {

  private static PacketTransformerService packetTransformerService;
  private static PacketDisplayService packetDisplayService;
  private static PcapFileReaderService pcapFileReaderService;
  private static LiveCaptureService liveCaptureService;
  private ServiceProvider() {
    throw new IllegalStateException("This util class cannot be instantiated");
  }

  public static PacketTransformerService getPacketTransformerService() {
    if (packetTransformerService == null) {
      packetTransformerService = new PacketTransformerService();
    }
    return packetTransformerService;
  }

  public static PacketDisplayService getPacketDisplayService() {
    if (packetDisplayService == null) {
      packetDisplayService = new PacketDisplayService();
    }
    return packetDisplayService;
  }

  public static PcapFileReaderService getPcapFileReaderService() {
    if (pcapFileReaderService == null) {
      pcapFileReaderService = new PcapFileReaderService(getPacketTransformerService());
    }
    return pcapFileReaderService;
  }

  public static LiveCaptureService getLiveCaptureService() {
    if (liveCaptureService == null) {
      liveCaptureService = new LiveCaptureService();
    }
    return liveCaptureService;
  }
}
