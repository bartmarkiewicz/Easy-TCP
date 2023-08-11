package controller;

import model.EasyTCPacket;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.io.EOFException;
import java.io.File;
import java.time.Instant;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

public class PacketLogger extends JTextPane {
    private static final Logger LOGGER = LoggerFactory.getLogger(PacketLogger.class);
    private static final ConcurrentHashMap<String, String> resolvedHostNames = new ConcurrentHashMap<>();
    public PacketLogger() {
        super();
        this.setEditable(false);
    }

    public void readPacketFile(File packetFile) throws PcapNativeException, NotOpenException {
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(packetFile.getPath(), PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(packetFile.getPath());
        }
        LOGGER.debug("File successfully read");
        StringBuilder textPaneText = new StringBuilder();
        var packetList = new ArrayList<EasyTCPacket>();
        while(true) {
            try {
                //look into transport layer packets
                var packet = handle.getNextPacketEx();
                var tcpPacket = packet.get(TcpPacket.class);
                var ipPacket = packet.get(IpPacket.class);
                var easyTCPacket = EasyTCPacket.fromPackets(ipPacket, tcpPacket, handle.getTimestamp(), resolvedHostNames);
                packetList.add(easyTCPacket);
            } catch (TimeoutException e) {
                LOGGER.debug("Timeout");

            } catch (EOFException e) {
                LOGGER.debug("EOF");
                break;
            }
        }
        var timeNow = Instant.now().toEpochMilli();
        LOGGER.debug("Setting text");
        this.setText(packetList.stream().map(i -> i.toString() + "\n").collect(Collectors.joining("\n")));
        LOGGER.debug("Stream end, it took %s ms to execute set text"
          .formatted(Instant.now().toEpochMilli() - timeNow));
        repaint();
        revalidate();
        handle.close();
    }
}
