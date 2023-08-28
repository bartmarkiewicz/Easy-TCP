package easytcp.service;

import easytcp.model.CaptureStatus;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.view.options.CaptureDescriptionPanel;
import easytcp.view.options.MiddleRow;
import easytcp.view.options.OptionsPanel;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;

import javax.swing.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class LiveCaptureServiceTest {


  @Mock
  private PacketDisplayService packetDisplayService;

  private FiltersForm filtersForm = FiltersForm.getInstance();
  private CaptureData captureData = CaptureData.getInstance();

  @Mock
  private ServiceProvider serviceProvider;

  @InjectMocks
  private LiveCaptureService liveCaptureService;

  @Test
  public void startCapture_assertHandleReturned() throws PcapNativeException, NotOpenException, InterruptedException {
    var networkInterface = Pcaps.findAllDevs().get(0);
    var optionsPanel = mock(OptionsPanel.class);
    var result = liveCaptureService.startCapture(
        networkInterface, filtersForm, new JTextPane(), optionsPanel);
    assertThat(result.isOpen()).isTrue();
    var appStatus = ApplicationStatus.getStatus();

    assertThat(appStatus.isLiveCapturing()).isTrue();
    assertThat(appStatus.getMethodOfCapture()).isEqualTo(CaptureStatus.LIVE_CAPTURE);

    result.breakLoop();
    result.close();
  }

  @Test
  public void setLogTextPane_whenEmptyCaptureData() {
    var textPane = new JTextPane();
    var optionsPanel = mock(OptionsPanel.class);

    var mr = mock(MiddleRow.class);
    var cap = mock(CaptureDescriptionPanel.class);

    when(optionsPanel.getMiddleRow()).thenReturn(mr);
    when(optionsPanel.getCaptureDescriptionPanel()).thenReturn(cap);


    LiveCaptureService.setLogTextPane(filtersForm, textPane, captureData, packetDisplayService, optionsPanel);

    assertThat(textPane.getText())
      .isEqualToIgnoringWhitespace("""
        <html>
          <head>

          </head>
          <body>
            <p style="margin-top: 0">
              
            </p>
          </body>
        </html>
        """);

    verify(mr).setConnectionStatusLabel(captureData);
    verify(cap).updateCaptureStats(captureData);
  }
}