package easytcp.service;

import easytcp.model.CaptureStatus;
import easytcp.model.IPprotocol;
import easytcp.model.PcapCaptureData;
import easytcp.model.TCPFlag;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpWindowScaleOption;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpOptionKind;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.*;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

public class PacketTransformerService {
  private static final Logger LOGGER = LoggerFactory.getLogger(PacketTransformerService.class);
  private static AtomicInteger threadsInProgress = new AtomicInteger(0);
  private static final ArrayList<PcapCaptureData> pcapCaptureData = new ArrayList<>();

  /* Transforms the Pcap4j objects into an EasyTCP packet, connection and other data
   */
  public EasyTCPacket fromPackets(IpPacket ipPacket,
                                  TcpPacket tcpPacket,
                                  Timestamp timestamp,
                                  CaptureData captureData,
                                  FiltersForm filtersForm) {
    var easyTcpPacket = new EasyTCPacket();
    var ipHeader = ipPacket.getHeader();
    if (ipHeader.getVersion().equals(IpVersion.IPV4)) {
      easyTcpPacket.setiPprotocol(IPprotocol.IPV4);
    } else if (ipPacket.getHeader().getVersion().equals(IpVersion.IPV6)) {
      easyTcpPacket.setiPprotocol(IPprotocol.IPV6);
    } else {
      throw new IllegalStateException("Invalid IP packet version");
    }
    var tcpHeader = tcpPacket.getHeader();
    easyTcpPacket.setAckNumber(tcpHeader.getAcknowledgmentNumberAsLong());
    easyTcpPacket.setTcpFlags(
      Map.ofEntries(
        Map.entry(TCPFlag.URG, tcpHeader.getUrg()),
        Map.entry(TCPFlag.PSH, tcpHeader.getPsh()),
        Map.entry(TCPFlag.RST, tcpHeader.getRst()),
        Map.entry(TCPFlag.ACK, tcpHeader.getAck()),
        Map.entry(TCPFlag.FIN, tcpHeader.getFin()),
        Map.entry(TCPFlag.SYN, tcpHeader.getSyn())
      ));
    setAddressesAndHostnames(
      ipHeader, tcpHeader, easyTcpPacket, captureData.getResolvedHostnames());
    easyTcpPacket.setTimestamp(timestamp);
    easyTcpPacket.setSequenceNumber(tcpHeader.getSequenceNumberAsLong());
    easyTcpPacket.setWindowSize(tcpHeader.getWindowAsInt());
    easyTcpPacket.setTcpOptions(tcpHeader.getOptions());
    easyTcpPacket.setHeaderPayloadLength(tcpHeader.length());
    easyTcpPacket.setDataPayloadLength(tcpPacket.getRawData().length - tcpHeader.length());
    setTcpConnection(easyTcpPacket, captureData.getTcpConnectionMap(), filtersForm);

    return easyTcpPacket;
  }

  /*
   * Sets up a tcp connection on the packet and the hashmap, needs to be synchronised due to this being
   * done in parallel, and so the same tcp connection isn't created multiple times.
   */
  private synchronized void setTcpConnection(EasyTCPacket easyTcpPacket,
                                             ConcurrentMap<ConnectionAddresses, TCPConnection> tcpConnectionHashMap,
                                             FiltersForm filtersForm) {
    List<String> interfaceAddresses;
    // extracts the capturing device interface address
    if (ApplicationStatus.getStatus().getMethodOfCapture() == CaptureStatus.LIVE_CAPTURE) {
      interfaceAddresses = filtersForm.getSelectedInterface() != null
        ? filtersForm.getSelectedInterface().getAddresses().stream()
        .map(pcapAddress ->  pcapAddress.getAddress().getHostAddress()).collect(Collectors.toList())
        : new ArrayList<>();
    } else {
      interfaceAddresses = new ArrayList<>();
    }

    // when reading a file, interface address is not known from the .pcap file, though usually it begins with 192 or 172
    if (easyTcpPacket.getSourceAddress().getAlphanumericalAddress().startsWith("192") //private address ranges
      || easyTcpPacket.getSourceAddress().getAlphanumericalAddress().startsWith("172")) {
      interfaceAddresses.add(easyTcpPacket.getSourceAddress().getAddressString());
    }
    if (easyTcpPacket.getDestinationAddress().getAlphanumericalAddress().startsWith("192") //private address ranges
      || easyTcpPacket.getDestinationAddress().getAlphanumericalAddress().startsWith("172")) {
      interfaceAddresses.add(easyTcpPacket.getDestinationAddress().getAddressString());
    } else {
      LOGGER.debug("Unclear which is the interface address %s or %s".formatted(
        easyTcpPacket.getDestinationAddress(), easyTcpPacket.getSourceAddress()));
    }

    var addressOfConnection = new ConnectionAddresses(easyTcpPacket.getSourceAddress(), easyTcpPacket.getDestinationAddress());
    //retrieves an existing connection or creates a new one
    final var tcpConnection = tcpConnectionHashMap.getOrDefault(addressOfConnection, new TCPConnection());

    tcpConnection.setConnectionAddresses(addressOfConnection);

    //determines if its an outgoing or incoming packet
    //this checks if both addresses are suspected of being client interface addresses
    if (interfaceAddresses.contains(easyTcpPacket.getDestinationAddress().getAddressString())
        && interfaceAddresses.contains(easyTcpPacket.getSourceAddress().getAddressString())) {
      if (tcpConnection.getPacketContainer().getPackets().size() > 0) {
        if (tcpConnection.getPacketContainer().getPackets().get(0).getDestinationAddress().equals(easyTcpPacket.getDestinationAddress())) {
          easyTcpPacket.setOutgoingPacket(tcpConnection.getPacketContainer().getPackets().get(0).getOutgoingPacket());
        } else {
          easyTcpPacket.setOutgoingPacket(!tcpConnection.getPacketContainer().getPackets().get(0).getOutgoingPacket());
        }
      } else {
        easyTcpPacket.setOutgoingPacket(true);
      }
    } else if (interfaceAddresses.contains(easyTcpPacket.getDestinationAddress().getAddressString())) {
      addressOfConnection = new ConnectionAddresses(easyTcpPacket.getSourceAddress(), easyTcpPacket.getDestinationAddress());
      //retrieves an existing connection or creates a new one
      tcpConnection.setConnectionAddresses(addressOfConnection);
      easyTcpPacket.setOutgoingPacket(false);
    } else {
      addressOfConnection = new ConnectionAddresses(easyTcpPacket.getDestinationAddress(), easyTcpPacket.getSourceAddress());
      easyTcpPacket.setOutgoingPacket(true);
      tcpConnection.setConnectionAddresses(addressOfConnection);
    }

    //sets handshake-specific information on the connection
    if (easyTcpPacket.getTcpFlags().get(TCPFlag.SYN) && easyTcpPacket.getOutgoingPacket()) {
      var mssClient = getMssFromPkt(easyTcpPacket);
      var windowScale = getWindowScaleFromPkt(easyTcpPacket);
      mssClient.ifPresent(integer -> tcpConnection.setMaximumSegmentSizeClient((long) integer));
      windowScale.ifPresent(tcpConnection::setWindowScaleClient);
    } else if (easyTcpPacket.getTcpFlags().get(TCPFlag.SYN)) {
      var mssServer = getMssFromPkt(easyTcpPacket);
      var windowScale = getWindowScaleFromPkt(easyTcpPacket);
      mssServer.ifPresent(integer -> tcpConnection.setMaximumSegmentSizeServer((long) integer));
      windowScale.ifPresent(tcpConnection::setWindowScaleServer);
    }

    //stores the packet in the tcp connection
    tcpConnection.getPacketContainer().addPacketToContainer(easyTcpPacket);
    //stores the tcp connection in a hashmap of address-connection
    tcpConnectionHashMap.put(addressOfConnection, tcpConnection);
    //adds the connection reference to the packet itself
    easyTcpPacket.setTcpConnection(tcpConnection);
    //determines the current status of connection following the adding of this packet
    determineStatusOfConnection(tcpConnection, easyTcpPacket);
  }

  private Optional<Integer> getMssFromPkt(EasyTCPacket easyTcpPacket) {
    return easyTcpPacket.getTcpOptions()
      .stream()
      .filter(opt -> opt.getKind().equals(TcpOptionKind.MAXIMUM_SEGMENT_SIZE))
      .map(opt -> ((TcpMaximumSegmentSizeOption) opt).getMaxSegSizeAsInt())
      .findFirst();
  }

  private Optional<Integer> getWindowScaleFromPkt(EasyTCPacket easyTcpPacket) {
    return easyTcpPacket.getTcpOptions()
      .stream()
      .filter(opt -> opt.getKind().equals(TcpOptionKind.WINDOW_SCALE))
      .map(opt -> ((TcpWindowScaleOption) opt).getShiftCountAsInt())
      .findFirst();
  }

  /* Determines the status of the connection as of the latest packet
   */
  private synchronized void determineStatusOfConnection(
    TCPConnection tcpConnection, EasyTCPacket easyTCPacket) {

    var packetList = tcpConnection.getPacketContainer().getPackets();
    var i = 1;

    // gets latest packet for the purpose of seeing if it had changed the connection,
    // rather than checking the packet just added - due to this being done asynchronously,
    // its not always the current packet that is the latest
    var latestPacket = packetList.get(packetList.size() - i);

    if (!easyTCPacket.equals(latestPacket)) {
      LOGGER.debug("Latest packet is not the current packet unfortunately");
    }

    var packetBeingAcked =
      tcpConnection.getPacketContainer()
        .findLatestPacketWithSeqNumberLessThan(latestPacket.getAckNumber(), !latestPacket.getOutgoingPacket());
    var latestPacketFlags = latestPacket.getTcpFlags();

    //default status is unknown
    if (tcpConnection.getConnectionStatus() == null) {
      tcpConnection.setConnectionStatus(ConnectionStatus.UNKNOWN);
    } else if (tcpConnection.getConnectionStatus() == ConnectionStatus.TIME_WAIT) {
      //time to wait for closing a connection cannot be determined, so the connection is closed on the arrival of another packet
      //then it goes through the state transition
      tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
    }

    //state transitions are done through this switch based on current tcp connection status
    //it determines if the status had been changed based on the latest packet and sets it if so
    switch (tcpConnection.getConnectionStatus()) {
      case CLOSED -> {
        if (latestPacketFlags.get(TCPFlag.SYN)) {
          tcpConnection.setFullConnection(true);
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
        } else if (latestPacketFlags.get(TCPFlag.SYN)
          && latestPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
          tcpConnection.setFullConnection(true);
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
        } else if (latestPacketFlags.get(TCPFlag.RST)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.REJECTED);
        }
      }
      case SYN_SENT -> {
        tcpConnection.setFullConnection(true);
        LOGGER.debug("SYN SENT");
        if (latestPacketFlags.get(TCPFlag.SYN)
          && latestPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
        } else if (latestPacketFlags.get(TCPFlag.SYN)) {
          // simultaneous open
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
        } else if (latestPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
        }
      }
      case SYN_RECEIVED -> {
        tcpConnection.setFullConnection(true);
        LOGGER.debug("SYN received");
        if (!latestPacket.getOutgoingPacket()
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
        }
      }
      case ESTABLISHED -> {
        LOGGER.debug("Established");
        if (!latestPacket.getOutgoingPacket()
          && latestPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSE_WAIT);
        } else if (latestPacket.getOutgoingPacket()
          && latestPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_1);
        } else if (latestPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSE_WAIT);
        }
      }
      case CLOSE_WAIT -> {
        LOGGER.debug("close wait");

        if (latestPacket.getOutgoingPacket()
          && latestPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.LAST_ACK);
        }
      }
      case LAST_ACK -> {
        LOGGER.debug("last ack");
        if (!latestPacket.getOutgoingPacket()
          && latestPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
        } else if (latestPacketFlags.get(TCPFlag.SYN) && !latestPacketFlags.get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
        } else if (latestPacketFlags.get(TCPFlag.SYN)
                && latestPacketFlags.get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
        } else if (packetBeingAcked.isPresent()
                && packetBeingAcked.get().getTcpFlags().get(TCPFlag.RST)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.REJECTED);
        }
      }
      case FIN_WAIT_1 -> {
        LOGGER.debug("fin wait");

        if (latestPacket.getOutgoingPacket()
          && latestPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)
          && !packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSING);
        } else if (latestPacket.getOutgoingPacket()
          && latestPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.TIME_WAIT);
        } else if (!latestPacket.getOutgoingPacket()
          && latestPacketFlags.get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_2);
        }
      }
      case FIN_WAIT_2 -> {
        LOGGER.debug("fin wait 2");

        if (latestPacket.getOutgoingPacket()
          && latestPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.TIME_WAIT);
        }
      }
      case TIME_WAIT -> LOGGER.debug("time wait");
      case UNKNOWN -> {
        LOGGER.debug("unknown");
        if (latestPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
        } else if (latestPacketFlags.get(TCPFlag.RST)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.REJECTED);
        } else if (latestPacketFlags.get(TCPFlag.SYN) && !latestPacketFlags.get(TCPFlag.ACK)) {
          tcpConnection.setFullConnection(true);
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
        } else if (latestPacketFlags.get(TCPFlag.SYN)
          && latestPacketFlags.get(TCPFlag.ACK)) {
          tcpConnection.setFullConnection(true);
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
        } else if (packetBeingAcked.isPresent() && packetBeingAcked.get().getTcpFlags().get(TCPFlag.RST)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.REJECTED);
        } else if (packetBeingAcked.isPresent()) {
          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
        }
      }
    }
  }

  /*
   * Sets addresses and hostnames for the tcp packet, resolves hostnames
   * even if the filter option is disabled, host names are still resolved immediately,
   * otherwise it would be very slow to resolve them after the user toggled the display.
   * Packet is printed immediately with IP, once the resolved hostname is available, it prints that (if filter is enabled).
   */
  private synchronized void setAddressesAndHostnames(
      IpPacket.IpHeader ipHeader, TcpPacket.TcpHeader tcpHeader, EasyTCPacket packet, ConcurrentMap<String, String> resolvedHostNames) {

    var destHostName = resolvedHostNames.get(String.valueOf(ipHeader.getDstAddr().getHostAddress()));
    var destinationAddress = new InternetAddress(
      ipHeader.getDstAddr().getHostAddress(), destHostName, ipHeader.getDstAddr(), tcpHeader.getDstPort().valueAsInt());
    packet.setDestinationAddress(destinationAddress);
    if (destHostName == null) {
      var executor = Executors.newSingleThreadExecutor();
      executor.execute(() -> {
        // resolving a hostname is a heavy operation so it needs to be done on another thread
        // to not hang the application
        threadsInProgress.incrementAndGet();
        var resolvedHostname = ipHeader.getDstAddr().getHostName();
        // is added to a hashmap to allow it to retrieve it from there rather than doing another
        // slow DNS call or cache lookup through pcap4j's .getHostName()
        // when doing another capture and the same address is spotted
        resolvedHostNames.put(String.valueOf(ipHeader.getDstAddr().getHostAddress()), resolvedHostname);
        destinationAddress.setHostName(resolvedHostname);
        threadsInProgress.decrementAndGet();
      });
      executor.shutdown();
    }
    var srcHostName = resolvedHostNames.get(String.valueOf(ipHeader.getSrcAddr().getHostAddress()));
    var sourceAddress = new InternetAddress(
      ipHeader.getSrcAddr().getHostAddress(), srcHostName, ipHeader.getSrcAddr(), tcpHeader.getSrcPort().valueAsInt());
    packet.setSourceAddress(sourceAddress);
    if (srcHostName == null) {
      var executor = Executors.newSingleThreadExecutor();
      executor.execute(() -> {
        threadsInProgress.incrementAndGet();
        var resolvedHostname = ipHeader.getSrcAddr().getHostName();
        resolvedHostNames.put(String.valueOf(ipHeader.getSrcAddr().getHostAddress()), resolvedHostname);
        sourceAddress.setHostName(resolvedHostname);
        threadsInProgress.decrementAndGet();
        LOGGER.debug("thread count %s".formatted(threadsInProgress.get()));
      });
      executor.shutdown();
    }
  }
  /* Stores pcap4j packets, for later conversion, when file reading.
  */
  public synchronized void storePcap4jPackets(IpPacket ipPacket, TcpPacket tcpPacket, Timestamp timestamp) {
    pcapCaptureData.add(new PcapCaptureData(tcpPacket, ipPacket, timestamp));
  }

  /*Transforms pcap file packet data sequentially in timestamp order
   */
  public void transformCapturedPackets() {
    var ff = FiltersForm.getInstance();
    var captureData = CaptureData.getInstance();
    pcapCaptureData.sort(Comparator.comparing(PcapCaptureData::timestamp));
    for (PcapCaptureData pcapCaptureDataItem : pcapCaptureData) {
      captureData.getPackets().addPacketToContainer(
        fromPackets(pcapCaptureDataItem.ipPacket(), pcapCaptureDataItem.tcpPacket(),
          pcapCaptureDataItem.timestamp(), captureData, ff));
    }
  }

  public static List<PcapCaptureData> getPcapCaptureData() {
    return pcapCaptureData;
  }
}
