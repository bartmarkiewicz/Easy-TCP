package controller;

import model.EasyTCPacket;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;

import javax.swing.*;
import java.io.EOFException;
import java.io.File;
import java.util.concurrent.TimeoutException;

public class PacketLogger extends JTextPane {
    private static final int COUNT = 5;

    private static final String PCAP_FILE_KEY = "tcpAmazonYoutube.pcapFile";
    private static final String PCAP_FILE =
      System.getProperty(PCAP_FILE_KEY, "src/main/resources/tcpAmazonYoutube");

    public PacketLogger() {
        super();
    }
    public void readPacketFile(File packetFile) throws PcapNativeException, NotOpenException {
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(packetFile.getPath(), PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(packetFile.getPath());
        }
        StringBuilder textPaneText = new StringBuilder();
        for (int i = 0; i < 2; i++) {
            try {
                //look into transport layer packets
                var packet = handle.getNextPacketEx();
                var tcpPacket = packet.get(TcpPacket.class);
                var ipPacket = packet.get(IpPacket.class);
                if (ipPacket != null && tcpPacket != null) {
                    textPaneText.append(EasyTCPacket.fromPackets(ipPacket, tcpPacket, handle.getTimestamp()).toString());
                }
            } catch (TimeoutException e) {
                System.out.println("timeout");
            } catch (EOFException e) {
                System.out.println("EOF");
                break;
            }
        }
        handle.close();
        this.setText(textPaneText.toString());
        repaint();
        revalidate();
    }
}
