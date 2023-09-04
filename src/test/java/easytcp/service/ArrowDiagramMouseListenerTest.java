package easytcp.service;

import easytcp.TestUtils;
import easytcp.model.packet.TCPConnection;
import easytcp.view.ArrowDiagram;
import easytcp.view.PacketLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.awt.event.MouseEvent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ArrowDiagramMouseListenerTest {
    @Mock
    private ArrowDiagram arrowDiagram;

    @Mock
    private PacketLog packetLog;

    @InjectMocks
    private ArrowDiagramMouseListener arrowDiagramMouseListener;
    private TCPConnection tcpConnection;

    @BeforeEach
    void setUp() {
        //contains 6 packets
        tcpConnection = TestUtils.getConnectionWithHandshakeAndFin();
        arrowDiagramMouseListener.setSelectedConnection(tcpConnection);
    }

    @Test
    void mouseClicked_whenFirstPacketClicked() {
        var mouseEventMock = mock(MouseEvent.class);
        when(mouseEventMock.getX()).thenReturn(0);
        when(mouseEventMock.getY()).thenReturn(140);
        arrowDiagramMouseListener.mouseClicked(mouseEventMock);
        assertThat(arrowDiagramMouseListener.getSelectedPacket())
                .isEqualTo(tcpConnection.getPacketContainer().getPackets().get(0));
        assertThat(tcpConnection.getPacketContainer().getPackets().get(0).getSelectedPacket())
                .isTrue();
        //asserts method calls
        verify(arrowDiagram)
                .setSelectedPacket(tcpConnection.getPacketContainer().getPackets().get(0), false);
        verify(packetLog)
                .refreshPacketLog(true);
    }

    @Test
    void mouseClicked_whenSecondPacketClicked() {
        var mouseEventMock = mock(MouseEvent.class);
        when(mouseEventMock.getX()).thenReturn(0);
        when(mouseEventMock.getY()).thenReturn(150);
        arrowDiagramMouseListener.mouseClicked(mouseEventMock);
        assertThat(arrowDiagramMouseListener.getSelectedPacket())
                .isEqualTo(tcpConnection.getPacketContainer().getPackets().get(1));
        assertThat(tcpConnection.getPacketContainer().getPackets().get(1).getSelectedPacket())
                .isTrue();
        //asserts method calls
        verify(arrowDiagram)
                .setSelectedPacket(tcpConnection.getPacketContainer().getPackets().get(1), false);
        verify(packetLog)
                .refreshPacketLog(true);
    }

    @Test
    void mouseClicked_whenThirdPacketClicked() {
        var mouseEventMock = mock(MouseEvent.class);
        when(mouseEventMock.getX()).thenReturn(0);
        when(mouseEventMock.getY()).thenReturn(300);
        arrowDiagramMouseListener.mouseClicked(mouseEventMock);
        assertThat(arrowDiagramMouseListener.getSelectedPacket())
                .isEqualTo(tcpConnection.getPacketContainer().getPackets().get(2));
        assertThat(tcpConnection.getPacketContainer().getPackets().get(2).getSelectedPacket())
                .isTrue();
        //asserts method calls
        verify(arrowDiagram)
                .setSelectedPacket(tcpConnection.getPacketContainer().getPackets().get(2), false);
        verify(packetLog)
                .refreshPacketLog(true);
    }


    @Test
    void mouseClicked_whenNoPacketClicked_aboveArrowDiagramClick() {
        var mouseEventMock = mock(MouseEvent.class);
        when(mouseEventMock.getY()).thenReturn(50);
        arrowDiagramMouseListener.mouseClicked(mouseEventMock);
        assertThat(arrowDiagramMouseListener.getSelectedPacket())
                .isNull();
        verifyNoInteractions(packetLog);
        verifyNoInteractions(arrowDiagram);
    }

    @Test
    void mouseClicked_whenNoConnectionSelected() {
        var mouseEventMock = mock(MouseEvent.class);
        arrowDiagramMouseListener.setSelectedConnection(null);
        arrowDiagramMouseListener.mouseClicked(mouseEventMock);
        assertThat(arrowDiagramMouseListener.getSelectedPacket())
                .isNull();
        verifyNoInteractions(packetLog);
        verifyNoInteractions(arrowDiagram);
    }

    @Test
    void mouseClicked_whenNoPacketClicked_tooFarDownClick() {
        var mouseEventMock = mock(MouseEvent.class);
        when(mouseEventMock.getX()).thenReturn(0);
        when(mouseEventMock.getY()).thenReturn(1300);
        arrowDiagramMouseListener.mouseClicked(mouseEventMock);
        assertThat(arrowDiagramMouseListener.getSelectedPacket())
                .isNull();
        verifyNoInteractions(packetLog);
        verifyNoInteractions(arrowDiagram);
    }
}