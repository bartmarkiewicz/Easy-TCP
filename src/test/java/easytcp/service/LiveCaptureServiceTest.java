package easytcp.service;

import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.view.CaptureDescriptionPanel;
import easytcp.view.MiddleRow;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

import javax.swing.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class LiveCaptureServiceTest {
  private final static int SNAPSHOT_LENGTH = 65536;
  private final static int READ_TIMEOUT = 10;

  @Mock
  private PacketTransformerService packetTransformerService;

  @Mock
  private PacketDisplayService packetDisplayService;

  private CaptureData captureData;
  private FiltersForm filtersForm;
  private CaptureDescriptionPanel captureDescriptionPanel;

  @Mock
  private ServiceProvider serviceProvider;

  @InjectMocks
  private LiveCaptureService liveCaptureService;

  @Before
  public void setUp() {
//    when(serviceProvider.getPacketTransformerService()).thenReturn(packetTransformerService);
//    when(serviceProvider.getPacketDisplayService()).thenReturn(packetDisplayService);
  }

  @Test
  public void startCapture_assertHandleReturned() throws PcapNativeException, NotOpenException, InterruptedException {
    var networkInterface = mock(PcapNetworkInterface.class);
    var handle = mock(PcapHandle.class);
    when(networkInterface.openLive(SNAPSHOT_LENGTH, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT))
      .thenReturn(handle);
//    doThrow(PcapNativeException.class)
//      .when(handle).loop(eq(Integer.MAX_VALUE), any(PacketListener.class), any());
    var result = liveCaptureService.startCapture(
        networkInterface, filtersForm, new JTextPane(), new MiddleRow(filtersForm), captureDescriptionPanel);
    Thread.sleep(2000);
    assertThat(result).isEqualTo(handle);
  }
}