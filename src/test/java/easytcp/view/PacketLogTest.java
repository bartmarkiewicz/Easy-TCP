package easytcp.view;

import easytcp.TestUtils;
import easytcp.model.PcapCaptureData;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.service.PacketDisplayService;
import easytcp.service.PacketTransformerService;
import easytcp.service.ServiceProvider;
import easytcp.service.capture.LiveCaptureService;
import easytcp.service.capture.PcapFileReaderService;
import easytcp.view.options.OptionsPanel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.util.List;
import java.util.concurrent.Executors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PacketLogTest {
    @Mock
    private ServiceProvider serviceProvider;
    @Mock
    private PcapFileReaderService pcapFileReaderService;
    @Mock
    private PacketDisplayService packetDisplayService;
    @Mock
    private LiveCaptureService liveCaptureService;

    private PacketLog packetLog;

    @BeforeEach
    void setUp() {
        when(serviceProvider.getPcapFileReaderService()).thenReturn(pcapFileReaderService);
        when(serviceProvider.getPacketDisplayService()).thenReturn(packetDisplayService);
        when(serviceProvider.getLiveCaptureService()).thenReturn(liveCaptureService);
        packetLog = new PacketLog(FiltersForm.getInstance(), serviceProvider);
    }

    @Test
    void readSelectedFile() throws InterruptedException {
        var mockFile = new File("testReadFile");
        var optionsPanel = mock(OptionsPanel.class);
        ApplicationStatus.getStatus().setLoading(false);
        ApplicationStatus.getStatus().setLiveCapturing(false);
        packetLog.readSelectedFile(mockFile, optionsPanel);
        Thread.sleep(300);
        verify(pcapFileReaderService)
            .readPacketFile(eq(mockFile), eq(FiltersForm.getInstance()), any(), eq(optionsPanel));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void readSelectedFile_whenAlreadyLoadingOrLiveCapturing(boolean loadingOrLiveCapture) throws InterruptedException {
        var mockFile = new File("testReadFile");
        var optionsPanel = mock(OptionsPanel.class);
        ApplicationStatus.getStatus().setLoading(loadingOrLiveCapture);
        ApplicationStatus.getStatus().setLiveCapturing(!loadingOrLiveCapture);
        //needs to be done on a seperate thread due to the JOptionPane appearing
        var executor = Executors.newSingleThreadExecutor();
        executor.execute(() -> packetLog.readSelectedFile(mockFile, optionsPanel));
        Thread.sleep(100);
        verifyNoInteractions(pcapFileReaderService);
        executor.shutdownNow();
    }

    @Test
    void newLog_assertDataCleared() throws InterruptedException {
        //needs a size to be present to instantiate an arrow diagram object
        ApplicationStatus.getStatus().setFrameDimension(new Dimension(500, 500));
        PacketTransformerService.getPcapCaptureData()
            .add(new PcapCaptureData(null, null, null));
        var captureData = CaptureData.getInstance();
        var con = TestUtils.createTCPConnection(false,
            TestUtils.createAddress("123", "fish"),
            TestUtils.createAddress("333", "notFish"));
        ArrowDiagram.getInstance().setTcpConnection(con, FiltersForm.getInstance());
        ArrowDiagram.getInstance().setScrollPane(new JScrollPane());
        captureData.getPackets().addPacketToContainer(
            TestUtils.createEasyTcpDataPacket(con,
                true, 3L,3L, 5, List.of()));
        packetLog.newLog();

        //needs to wait because most of the calls are on the Swing event dispatching thread.
        Thread.sleep(300);
        assertThat(captureData.getPackets().getPackets()).isEmpty();
        assertThat(ArrowDiagram.getInstance().getSelectedConnection())
            .isNull();
        assertThat(PacketTransformerService.getPcapCaptureData()).isEmpty();
    }
}