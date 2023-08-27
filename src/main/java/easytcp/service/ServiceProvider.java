package easytcp.service;

public class ServiceProvider {
  private static PacketTransformerService packetTransformerService;
  private static PacketDisplayService packetDisplayService;
  private static PcapFileReaderService pcapFileReaderService;
  private static ConnectionDisplayService connectionDisplayService;
  private static LiveCaptureService liveCaptureService;
  private static CaptureSaveService captureSaveService;
  private static ServiceProvider serviceProvider;

  public synchronized static ServiceProvider getInstance() {
    if (serviceProvider == null) {
      serviceProvider = new ServiceProvider();
    }
    return serviceProvider;
  }

  public synchronized PacketTransformerService getPacketTransformerService() {
    if (packetTransformerService == null) {
      packetTransformerService = new PacketTransformerService();
    }
    return packetTransformerService;
  }

  public synchronized PacketDisplayService getPacketDisplayService() {
    if (packetDisplayService == null) {
      packetDisplayService = new PacketDisplayService();
    }
    return packetDisplayService;
  }

  public synchronized PcapFileReaderService getPcapFileReaderService() {
    if (pcapFileReaderService == null) {
      pcapFileReaderService = new PcapFileReaderService(getPacketTransformerService());
    }
    return pcapFileReaderService;
  }

  public synchronized LiveCaptureService getLiveCaptureService() {
    if (liveCaptureService == null) {
      liveCaptureService = new LiveCaptureService(getInstance());
    }
    return liveCaptureService;
  }

  public synchronized ConnectionDisplayService getConnectionDisplayService() {
    if (connectionDisplayService == null) {
      connectionDisplayService = new ConnectionDisplayService();
    }
    return connectionDisplayService;
  }

  public synchronized  CaptureSaveService getCaptureSaveService() {
    if (captureSaveService == null) {
      captureSaveService = new CaptureSaveService();
    }
    return captureSaveService;
  }
}
