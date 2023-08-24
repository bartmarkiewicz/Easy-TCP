package easytcp.model;

import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;

import java.sql.Timestamp;


public record PcapCaptureData(TcpPacket tcpPacket, IpPacket ipPacket, Timestamp timestamp) {
}
