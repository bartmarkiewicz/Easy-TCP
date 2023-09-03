package easytcp.service.capture;

import easytcp.TestUtils;
import easytcp.service.PacketTransformerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.pcap4j.core.PcapHandle;

import java.sql.Timestamp;
import java.time.Instant;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FilePacketListenerTest {

  private FilePacketListener filePacketListener;

  @Mock
  private PcapHandle handle;

  @Mock
  private PacketTransformerService packetTransformerService;


  @BeforeEach
  void setUp() {
    filePacketListener = new FilePacketListener(packetTransformerService, handle);
  }

  @Test
  void gotPacket() throws Exception{
    var tcpPacket = TestUtils.createPcap4jTcpPacketBuilder();
    var ipPacket = TestUtils.createPcap4Packet(tcpPacket);
    var timestamp = Timestamp.from(Instant.now());
    when(handle.getTimestamp()).thenReturn(timestamp);
    filePacketListener.gotPacket(ipPacket);

    verify(packetTransformerService)
      .storePcap4jPackets(eq(ipPacket), eq(tcpPacket.build()), eq(timestamp));
  }
}