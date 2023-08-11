package controller;

import model.CaptureStats;
import model.EasyTCPacket;
import model.TCPFlag;
import org.apache.logging.log4j.util.Strings;
import org.pcap4j.core.*;
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

    private final FiltersForm filtersForm;
    private final ArrayList<EasyTCPacket> packets;
    private final CaptureStats captureStats;

    public PacketLogger(FiltersForm filtersForm) {
        super();
        this.filtersForm = filtersForm;
        this.packets = new ArrayList<>();
        this.setEditable(false);
        this.captureStats = new CaptureStats();
    }

    public void readPacketFile(File packetFile) throws PcapNativeException, NotOpenException {
        this.filtersForm.setReadingFromFile(true);
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(packetFile.getPath(), PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(packetFile.getPath());
        }
        LOGGER.debug("File successfully read");
        StringBuilder textPaneText = new StringBuilder();
        while(true) {
            try {
                //look into transport layer packets
                var packet = handle.getNextPacketEx();
                var tcpPacket = packet.get(TcpPacket.class);
                var ipPacket = packet.get(IpPacket.class);
                var easyTCPacket = EasyTCPacket.fromPackets(ipPacket, tcpPacket, handle.getTimestamp(), resolvedHostNames);
                packets.add(easyTCPacket);
            } catch (TimeoutException e) {
                LOGGER.debug("Timeout");

            } catch (EOFException e) {
                LOGGER.debug("EOF");
                break;
            }
        }
        var timeNow = Instant.now().toEpochMilli();
        LOGGER.debug("Setting text");
        this.setText(getPacketText());
        LOGGER.debug("Stream end, it took %s ms to execute set text"
          .formatted(Instant.now().toEpochMilli() - timeNow));
        setCaptureStats();
        repaint();
        revalidate();
        handle.close();
    }

    public void refilterPackets() {
        var packetText = getPacketText();
        if (Strings.isBlank(packetText)) {
            this.setText("No packets matching your search criteria found, try changing your filters.");
        } else {
            this.setText(packetText);
        }
        repaint();
        revalidate();
    }

    public CaptureStats getCaptureStats() {
        return captureStats;
    }

    private String getPacketText() {
        return packets.stream()
          .filter(packet -> packet.isVisible(filtersForm))
          .map(i -> i + "\n")
          .collect(Collectors.joining("\n"));
    }

    private void setCaptureStats() {
        this.captureStats.setPacketsCaptured(packets.size());
        this.captureStats.setTcpConnectionsEstablished(packets
          .stream()
          .filter(i -> i.getTcpFlags().get(TCPFlag.SYN))
          .map(i -> i.getDestinationAddress().getAddressString())
          .distinct()
          .count());
    }
}
