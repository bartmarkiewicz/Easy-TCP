package easytcp.service.capture;

import easytcp.model.CaptureStatus;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.service.PacketDisplayService;
import easytcp.service.PacketTransformerService;
import easytcp.service.ServiceProvider;
import easytcp.view.options.OptionsPanel;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.io.File;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class PcapFileReaderService {
  private static final Logger LOGGER = LoggerFactory.getLogger(PcapFileReaderService.class);
  private final PacketTransformerService packetTransformerService;
  private final PacketDisplayService packetDisplayService;
  private final CaptureData captureData;
  private AtomicBoolean isSettingText;

  public PcapFileReaderService(PacketTransformerService packetTransformerService) {
    this.packetTransformerService = packetTransformerService;
    this.packetDisplayService = ServiceProvider.getInstance().getPacketDisplayService();
    this.captureData = CaptureData.getInstance();
  }

  public CaptureData readPacketFile(File packetFile, FiltersForm filtersForm,
                                    JTextPane textPane, OptionsPanel optionsPanel) {
    var executor = Executors.newSingleThreadExecutor();
    captureData.clear();
    executor.execute(() -> {
      PcapHandle handle;
      try {
        handle = Pcaps.openOffline(packetFile.getPath(), PcapHandle.TimestampPrecision.MICRO);
      } catch (PcapNativeException e) {
        try {
          handle = Pcaps.openOffline(packetFile.getPath());
        } catch (PcapNativeException ex) {
          throw new RuntimeException(ex);
        }
      }

      var appStatus = ApplicationStatus.getStatus();
      appStatus.setMethodOfCapture(CaptureStatus.READING_FROM_FILE);
      appStatus.setLoading(true);
      captureData.clear();
      try (var finalHandle = handle) {
        this.isSettingText = new AtomicBoolean();
        isSettingText.set(false);
        var threadPool = Executors.newCachedThreadPool();
        int maxPackets = Integer.MAX_VALUE;
        finalHandle.setFilter(filtersForm.toBfpExpression(), BpfProgram.BpfCompileMode.OPTIMIZE);
        finalHandle.loop(maxPackets, new FilePacketListener(packetTransformerService, finalHandle), threadPool);
        captureData.clear();
        while (!threadPool.isTerminated()) {
          Thread.sleep(1000);
        }
        threadPool.shutdown();
        packetTransformerService.transformCapturedPackets();
        SwingUtilities.invokeLater(() -> {
          LiveCaptureService.setLogTextPane(filtersForm, textPane, captureData, packetDisplayService, optionsPanel);
          isSettingText.set(false);
        });
      } catch (Exception e) {
        LOGGER.debug(e.getMessage());
        LOGGER.debug("Error sniffing packet");
      } finally {
        appStatus.setLoading(false);
      }
    });
    executor.shutdown();
    return captureData;
  }
}
