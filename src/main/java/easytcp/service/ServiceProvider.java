package easytcp.service;

public class ServiceProvider {
  private static PacketTransformerService packetTransformerService;
  private static PacketDisplayService packetDisplayService;
  private static PcapFileReaderService pcapFileReaderService;
  private static LiveCaptureService liveCaptureService;
  private static ServiceProvider serviceProvider;

  public static ServiceProvider getInstance() {
    if (serviceProvider == null) {
      serviceProvider = new ServiceProvider();
    }
    return serviceProvider;
  }

  public PacketTransformerService getPacketTransformerService() {
    if (packetTransformerService == null) {
      packetTransformerService = new PacketTransformerService();
    }
    return packetTransformerService;
  }

  public PacketDisplayService getPacketDisplayService() {
    if (packetDisplayService == null) {
      packetDisplayService = new PacketDisplayService();
    }
    return packetDisplayService;
  }

  public PcapFileReaderService getPcapFileReaderService() {
    if (pcapFileReaderService == null) {
      pcapFileReaderService = new PcapFileReaderService(getPacketTransformerService());
    }
    return pcapFileReaderService;
  }

  public LiveCaptureService getLiveCaptureService() {
    if (liveCaptureService == null) {
      liveCaptureService = new LiveCaptureService(getInstance());
    }
    return liveCaptureService;
  }
}
