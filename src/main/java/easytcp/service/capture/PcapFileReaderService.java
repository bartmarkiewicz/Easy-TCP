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

//Service used for reading packet capture files
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
    captureData.clear(); //clears captured data

    //opens file on a new thread, to not freeze the UI.
    executor.execute(() -> {
      PcapHandle handle;
      try {
        handle = Pcaps.openOffline(packetFile.getPath(), PcapHandle.TimestampPrecision.MICRO);
      } catch (PcapNativeException e) {
        try {
          handle = Pcaps.openOffline(packetFile.getPath() + ".pcap");
        } catch (PcapNativeException ex) {
          throw new RuntimeException(ex);
        }
      }

      var appStatus = ApplicationStatus.getStatus();
      appStatus.setMethodOfCapture(CaptureStatus.READING_FROM_FILE);
      appStatus.setLoading(true);
      try {
        this.isSettingText = new AtomicBoolean();
        isSettingText.set(false);
        //each packet read from the file is read on a thread from the thread pool.
        var threadPool = Executors.newCachedThreadPool();
        int maxPackets = Integer.MAX_VALUE;
        handle.setFilter(filtersForm.toBfpExpression(), BpfProgram.BpfCompileMode.OPTIMIZE);
        handle.loop(maxPackets, new FilePacketListener(packetTransformerService, handle), threadPool);
        //ensures the thread pool is shut down, to save resources
        Thread.sleep(2000);
        threadPool.shutdown();
        //thread pool will terminate when the whole file has been read
        while (!threadPool.isTerminated()) {
          Thread.sleep(1000);
        }
        //once the thread-pool is terminated, we know the file has been entirely read,
        // we can then transform the captured pcap4j packets
        packetTransformerService.transformCapturedPackets();
        //updates the text displays on the UI thread
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
