package easytcp.service;

import easytcp.model.CaptureStatus;
import easytcp.model.IPprotocol;
import easytcp.model.TCPFlag;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.InternetAddress;
import easytcp.model.packet.TCPConnection;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class PacketTransformerService {
  private static final Logger LOGGER = LoggerFactory.getLogger(PacketTransformerService.class);
  private static AtomicInteger threadsInProgress = new AtomicInteger(0);

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
      ipHeader, tcpHeader, easyTcpPacket, captureData.getResolvedHostnames(), filtersForm);
    easyTcpPacket.setTimestamp(timestamp);
    easyTcpPacket.setSequenceNumber((long) tcpHeader.getSequenceNumber());
    easyTcpPacket.setWindowSize(tcpHeader.getWindowAsInt());
    easyTcpPacket.setTcpOptions(tcpHeader.getOptions());
    easyTcpPacket.setHeaderPayloadLength(tcpHeader.length());
    easyTcpPacket.setDataPayloadLength(tcpPacket.getRawData().length - tcpHeader.length());
    setTcpConnection(easyTcpPacket, captureData.getTcpConnectionMap(), filtersForm);

    return easyTcpPacket;
  }

  /**
   * Sets up a tcp connection on the packet and the hashmap, needs to be synchronised due to this being
   * done in parallel, and so the same tcp connection isn't created multiple times.
   * @param easyTcpPacket
   * @param tcpConnectionHashMap
   * @param filtersForm
   */
  private synchronized void setTcpConnection(EasyTCPacket easyTcpPacket,
                                             ConcurrentHashMap<InternetAddress, TCPConnection> tcpConnectionHashMap,
                                             FiltersForm filtersForm) {
    List<String> interfaceAddresses;
    // extracts the capturing device interface address
    if (ApplicationStatus.getStatus().getMethodOfCapture() == CaptureStatus.LIVE_CAPTURE) {
      interfaceAddresses = filtersForm.getSelectedInterface() != null
        ? filtersForm.getSelectedInterface().getAddresses().stream()
        .map(pcapAddress -> "/" + pcapAddress.getAddress().getHostAddress()).toList()
        : List.of();
    } else {
      interfaceAddresses = new ArrayList<>();
      // when reading a file, interface address is not known from the .pcap file, though usually it begins with 192 or 172
      if (easyTcpPacket.getSourceAddress().getAlphanumericalAddress().startsWith("/192") //private address ranges
        || easyTcpPacket.getSourceAddress().getAlphanumericalAddress().startsWith("/172")) {
        interfaceAddresses.add(easyTcpPacket.getSourceAddress().getAddressString());
      } else if (easyTcpPacket.getDestinationAddress().getAlphanumericalAddress().startsWith("/192") //private address ranges
        || easyTcpPacket.getDestinationAddress().getAlphanumericalAddress().startsWith("/172")) {
        interfaceAddresses.add(easyTcpPacket.getDestinationAddress().getAddressString());
      }
    }
    InternetAddress addressOfConnection;
    TCPConnection tcpConnection;
    if (interfaceAddresses.contains(easyTcpPacket.getDestinationAddress().getAlphanumericalAddress())) {
      // if dest address is an interface address it uses the src address as a key for the hashmap
      addressOfConnection = easyTcpPacket.getSourceAddress();
      tcpConnection = tcpConnectionHashMap.getOrDefault(addressOfConnection, new TCPConnection());
      if (tcpConnection.getHost() == null) {
        LOGGER.debug("Not found tcp connection for %s".formatted(addressOfConnection));
      }
      tcpConnection.setHost(addressOfConnection);
      tcpConnection.setHostTwo(easyTcpPacket.getDestinationAddress());
      easyTcpPacket.setOutgoingPacket(true);
    } else {
      addressOfConnection = easyTcpPacket.getDestinationAddress();
      tcpConnection = tcpConnectionHashMap.getOrDefault(addressOfConnection, new TCPConnection());
      if (tcpConnection.getHost() == null) {
        LOGGER.debug("Not found tcp connection for %s".formatted(addressOfConnection));
      }
      easyTcpPacket.setOutgoingPacket(false);
      tcpConnection.setHost(addressOfConnection);
      tcpConnection.setHostTwo(easyTcpPacket.getSourceAddress());
    }
    //stores the packet in the tcp connection
    tcpConnection.getPacketContainer().addPacketToContainer(easyTcpPacket);
    //stores the tcp connection in a hashmap of address-connection
    tcpConnectionHashMap.put(addressOfConnection, tcpConnection);
    //adds the connection reference to the packet itself
    easyTcpPacket.setTcpConnection(tcpConnection);
    determineStatusOfConnection(tcpConnection);

  }

  private void determineStatusOfConnection(
    TCPConnection tcpConnection) {
    var packetList = tcpConnection.getPacketContainer().getPackets();
    var i = 1;

    // gets latest packet for the purpose of seeing if it had changed the connection,
    // rather than checking the packet just added - due to this being done asynchronously,
    // its not always the current packet that is the latest
    var latestPacket = packetList.get(packetList.size() - i);

    var packetBeingAcked =
      tcpConnection.getPacketContainer()
        .findLatestPacketWithSeqNumberLessThan(latestPacket.getAckNumber());
    var latestPacketFlags = latestPacket.getTcpFlags();

    //default status is closed
    if (tcpConnection.getConnectionStatus() == null) {
      tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
    }

    // reset flag means the connection has been rejected, or disorderly terminated
    if (latestPacketFlags.get(TCPFlag.RST)) {
      tcpConnection.setConnectionStatus(ConnectionStatus.REJECTED);
    }

    //state transitions are done through this switch based on current tcp connection status
    switch (tcpConnection.getConnectionStatus()) {
      case CLOSED -> {
        //determine initial connection status
        if (latestPacketFlags.get(TCPFlag.SYN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
          tcpConnection.setFullConnection(true);
        } else if ((latestPacketFlags.get(TCPFlag.PSH) || latestPacket.getDataPayloadLength() > 20)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.PSH)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
        } else if (latestPacketFlags.get(TCPFlag.FIN) || latestPacketFlags.get(TCPFlag.ACK)) {
            tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
        } else if (latestPacketFlags.get(TCPFlag.SYN)
          && latestPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
        }
      }
      case SYN_SENT -> {
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
    }
  }

  /**
   * Sets addresses and hostnames for the tcp packet, resolves hostnames if enabled
   */
  private void setAddressesAndHostnames(IpPacket.IpHeader ipHeader,
                                        TcpPacket.TcpHeader tcpHeader,
                                        EasyTCPacket packet,
                                        ConcurrentHashMap<String, String> resolvedHostNames,
                                        FiltersForm filtersForm) {

    var destHostName = resolvedHostNames.get(String.valueOf(ipHeader.getDstAddr()));
    var destinationAddress = new InternetAddress(
      ipHeader.getDstAddr(), destHostName, ipHeader.getDstAddr(), tcpHeader.getDstPort());
    packet.setDestinationAddress(destinationAddress);
    if (filtersForm.isResolveHostnames() && destHostName == null) {
      new Thread(() -> {
        // resolving a hostname is a heavy operation so it needs to be done on another thread
        // to not hang the application
        threadsInProgress.incrementAndGet();
        var resolvedHostname = ipHeader.getDstAddr().getHostName();
        // is added to a hashmap to allow it to retrieve it from there rather than doing another
        // slow DNS call or cache lookup through pcap4j's .getHostName().
        resolvedHostNames.put(String.valueOf(ipHeader.getDstAddr()), resolvedHostname);
        destinationAddress.setHostName(resolvedHostname);
        threadsInProgress.decrementAndGet();
      }).start();
    }
    var srcHostName = resolvedHostNames.get(String.valueOf(ipHeader.getSrcAddr()));
    var sourceAddress = new InternetAddress(
      ipHeader.getSrcAddr(), srcHostName, ipHeader.getSrcAddr(), tcpHeader.getSrcPort());
    packet.setSourceAddress(sourceAddress);
    if (filtersForm.isResolveHostnames() && srcHostName == null) {
      new Thread(() -> {
        threadsInProgress.incrementAndGet();
        var resolvedHostname = ipHeader.getSrcAddr().getHostName();
        resolvedHostNames.put(String.valueOf(ipHeader.getSrcAddr()), resolvedHostname);
        sourceAddress.setHostName(resolvedHostname);
        threadsInProgress.decrementAndGet();
        LOGGER.debug("thread count %s".formatted(threadsInProgress.get()));
      }).start();
      LOGGER.debug("thread count, on easytcp.main thread %s".formatted(threadsInProgress.get()));
    }
  }
}
