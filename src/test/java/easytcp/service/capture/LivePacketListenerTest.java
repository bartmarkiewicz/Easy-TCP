package easytcp.service.capture;

import easytcp.TestUtils;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.EasyTCPacket;
import easytcp.service.PacketDisplayService;
import easytcp.service.PacketTransformerService;
import easytcp.view.options.OptionsPanel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.pcap4j.core.PcapHandle;

import javax.swing.*;
import java.sql.Timestamp;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LivePacketListenerTest {

  private LivePacketListener livePacketListener;
  @Mock
  private PcapHandle handle;
  @Mock
  private PacketTransformerService packetTransformerService;
  @Mock
  private FiltersForm filtersForm;
  private AtomicBoolean isSettingForm = new AtomicBoolean(false);
  @Mock
  private JTextPane textPane;
  @Mock
  private PacketDisplayService packetDisplayService;
  @Mock
  private OptionsPanel optionsPanel;

  @BeforeEach
  void setUp() {
    livePacketListener = new LivePacketListener(handle, packetTransformerService, CaptureData.getInstance(), filtersForm,
      isSettingForm, textPane, packetDisplayService, optionsPanel);
  }

  @Test
  void gotPacket() throws Exception {
    var pcap4jTCPacketBuilder = TestUtils.createPcap4jTcpPacketBuilder();
    var pcap4jIpPacket = TestUtils.createPcap4Packet(pcap4jTCPacketBuilder);
    var transformedPacket = new EasyTCPacket();
    ApplicationStatus.getStatus().setLiveCapturing(false);
    when(packetTransformerService.fromPackets(any(), any(), any(), any(), any()))
      .thenReturn(transformedPacket);
    when(handle.getTimestamp()).thenReturn(mock(Timestamp.class));
    livePacketListener.gotPacket(pcap4jIpPacket);

    assertThat(CaptureData.getCaptureData().getPackets().getPackets())
      .containsExactly(transformedPacket);

    verify(packetTransformerService).fromPackets(
      eq(pcap4jIpPacket), eq(pcap4jTCPacketBuilder.build()), any(), eq(CaptureData.getInstance()), eq(filtersForm));
  }
}