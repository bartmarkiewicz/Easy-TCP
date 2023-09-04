package easytcp.service.capture;

import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.service.PacketTransformerService;
import easytcp.view.options.OptionsPanel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.swing.*;
import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class PcapFileReaderServiceTest {
  private PcapFileReaderService pcapFileReaderService = new PcapFileReaderService(new PacketTransformerService());

  @Test
  void readPacketFile_successfullyRead() throws InterruptedException {
    CaptureData.getInstance().clear();
    PacketTransformerService.getPcapCaptureData().clear();
    FiltersForm.getInstance().restoreDefaults();
    var file = new File("src/test/resources/testPcapFile");
    var filters = FiltersForm.getInstance();
    var txtPane = mock(JTextPane.class);
    var optionsPanel = mock(OptionsPanel.class);
    var captureData = pcapFileReaderService.readPacketFile(file, filters, txtPane, optionsPanel);

    Thread.sleep(500);

    while(ApplicationStatus.getStatus().isLoading().get()) {
      Thread.sleep(500);
    }
    assertThat(captureData.getPackets().getPackets())
      .hasSize(732);
  }
}