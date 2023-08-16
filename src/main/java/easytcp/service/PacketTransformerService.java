package easytcp.service;

import easytcp.model.*;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.sql.Timestamp;
import java.util.*;
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
    setAddressesAndHostnames(ipHeader, easyTcpPacket, captureData.getResolvedHostnames(), filtersForm);
    easyTcpPacket.setTimestamp(timestamp);
    easyTcpPacket.setSequenceNumber(tcpHeader.getSequenceNumber());
    easyTcpPacket.setWindowSize(tcpHeader.getWindowAsInt());
    easyTcpPacket.setDataPayloadLength(tcpPacket.getRawData().length);
    easyTcpPacket.setTcpOptions(tcpHeader.getOptions());
    easyTcpPacket.setHeaderPayloadLength(tcpHeader.length());
    setTcpConnection(easyTcpPacket, captureData.getTcpConnectionMap(), filtersForm);

    return easyTcpPacket;
  }

  private void setTcpConnection(EasyTCPacket easyTcpPacket,
                                HashMap<InternetAddress, TCPConnection> tcpConnectionHashMap,
                                FiltersForm filtersForm) {
    var interfaceAddresses = filtersForm.getSelectedInterface() != null
      ? filtersForm.getSelectedInterface().getAddresses().stream()
      .map(pcapAddress -> "/" + pcapAddress.getAddress().getHostAddress()).toList()
      : List.of();
    InternetAddress addressOfConnection;
    TCPConnection tcpConnection;
    if (interfaceAddresses.contains(easyTcpPacket.getDestinationAddress().getAlphanumericalAddress())) {
      addressOfConnection = new InternetAddress(easyTcpPacket.getSourceAddress().getPcap4jAddress());
      tcpConnection = tcpConnectionHashMap.getOrDefault(addressOfConnection, new TCPConnection());
      tcpConnection.setHost(addressOfConnection);
      easyTcpPacket.setOutgoingPacket(true);
      tcpConnection.setHostTwo(new InternetAddress(easyTcpPacket.getDestinationAddress().getPcap4jAddress()));
    } else {
      addressOfConnection = new InternetAddress(easyTcpPacket.getDestinationAddress().getPcap4jAddress());
      tcpConnection = tcpConnectionHashMap.getOrDefault(addressOfConnection, new TCPConnection());
      easyTcpPacket.setOutgoingPacket(false);
      tcpConnection.setHost(addressOfConnection);
      tcpConnection.setHostTwo(new InternetAddress(easyTcpPacket.getSourceAddress().getPcap4jAddress()));
    }

    determineStatusOfConnection(tcpConnection, easyTcpPacket);


    tcpConnectionHashMap.put(addressOfConnection, tcpConnection);
    easyTcpPacket.setTcpConnection(tcpConnection);
  }

  private void determineStatusOfConnection(TCPConnection tcpConnection, EasyTCPacket easyTcpPacket) {
    //todo sort by timestamp, determine status of connection by latest packet
    tcpConnection.getPacketContainer().addPacketToContainer(easyTcpPacket);
    var packetList = tcpConnection.getPacketContainer().getPackets();
    var i = 1;
    var latestPacket = packetList.get(packetList.size() - i);
    while(latestPacket.getTcpFlags().get(TCPFlag.RST)) {
      i++;
      latestPacket = packetList.get(packetList.size() - i);
      if (i == 0) {
        LOGGER.info("Connection not established, only RST packets");
        break;
      }
    }
    //todo maybe add checks for current status
    if (latestPacket.getOutgoingPacket()
      && latestPacket.getTcpFlags().get(TCPFlag.SYN)
      && latestPacket.getTcpFlags().get(TCPFlag.ACK)) {
      tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
      LOGGER.info("Syn received, sending syn ack to complete TCP handshake between %s, %s"
        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));
    } else if (latestPacket.getOutgoingPacket() && latestPacket.getTcpFlags().get(TCPFlag.SYN)) {
      tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
      LOGGER.info("Started a tcp handshake between %s and %s"
        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));
    } else if (!latestPacket.getOutgoingPacket() //if incoming packet with SYN and an ACK for the syn
      && latestPacket.getTcpFlags().get(TCPFlag.SYN)
      && latestPacket.getTcpFlags().get(TCPFlag.ACK)) {
      tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
      LOGGER.info("Established TCP connection between %s and %s"
        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));
    } else if (latestPacket.getOutgoingPacket() && latestPacket.getTcpFlags().get(TCPFlag.FIN)) {
      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status FIN_WAIT_1"
        .formatted(
          tcpConnection.getConnectionStatus(),
          tcpConnection.getHost().getAddressString(),
          tcpConnection.getHostTwo().getAddressString()));
      tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_1); // active close
    } else if (!latestPacket.getOutgoingPacket()
      && latestPacket.getTcpFlags().get(TCPFlag.FIN)
      && latestPacket.getTcpFlags().get(TCPFlag.ACK)) {
      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status CLOSE WAIT"
        .formatted(
          tcpConnection.getConnectionStatus(),
          tcpConnection.getHost().getAddressString(),
          tcpConnection.getHostTwo().getAddressString()));
      tcpConnection.setConnectionStatus(ConnectionStatus.CLOSE_WAIT); // passive close
    } else if (!latestPacket.getOutgoingPacket()
      && tcpConnection.getConnectionStatus() == ConnectionStatus.CLOSE_WAIT
      && latestPacket.getTcpFlags().get(TCPFlag.ACK)
      && !latestPacket.getTcpFlags().get(TCPFlag.FIN)) {
      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status FIN_WAIT_2"
        .formatted(
          tcpConnection.getConnectionStatus(),
          tcpConnection.getHost().getAddressString(),
          tcpConnection.getHostTwo().getAddressString()));
      tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_2); // passive close
    } else if (!latestPacket.getOutgoingPacket()
      && latestPacket.getTcpFlags().get(TCPFlag.FIN)) {
      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status TIME_WAIT"
        .formatted(
          tcpConnection.getConnectionStatus(),
          tcpConnection.getHost().getAddressString(),
          tcpConnection.getHostTwo().getAddressString()));
      tcpConnection.setConnectionStatus(ConnectionStatus.TIME_WAIT); // passive close
    } else if (latestPacket.getOutgoingPacket()
      && latestPacket.getTcpFlags().get(TCPFlag.ACK)
      && tcpConnection.getConnectionStatus() == ConnectionStatus.TIME_WAIT) {
      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status CLOSED"
        .formatted(
          tcpConnection.getConnectionStatus(),
          tcpConnection.getHost().getAddressString(),
          tcpConnection.getHostTwo().getAddressString()));
      tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED); // passive close
    } else if (latestPacket.getTcpFlags().get(TCPFlag.PSH)
      && latestPacket.getTcpFlags().get(TCPFlag.ACK)
      && !latestPacket.getTcpFlags().get(TCPFlag.RST)){
//      LOGGER.info("Connections probably is live between %s and %s"
//        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));
      tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED); //probably established
    } else if (latestPacket.getTcpFlags().get(TCPFlag.RST)) {
      LOGGER.info("Connection unexpected, disorderly close between %s and %s"
        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));

    }
//
//
//    else if (easyTcpPacket.getTcpFlags().get(TCPFlag.PSH)) {
//      //todo is this right?
//      tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
//    } else if (easyTcpPacket.getTcpFlags().get(TCPFlag.FIN) && easyTcpPacket.getTcpFlags().get(TCPFlag.ACK)) {
//      //todo is this right?
//      tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
//    } //else {
////      tcpConnection.setConnectionStatus(ConnectionStatus.UNKNOWN);
////    }

  }

  private void setAddressesAndHostnames(IpPacket.IpHeader ipHeader,
                                        EasyTCPacket packet,
                                        ConcurrentHashMap<String, String> resolvedHostNames,
                                        FiltersForm filtersForm) {
    var destHostName = resolvedHostNames.get(String.valueOf(ipHeader.getDstAddr()));
    var destinationAddress = new InternetAddress(
      ipHeader.getDstAddr(), destHostName, ipHeader.getDstAddr());
    packet.setDestinationAddress(destinationAddress);
    if (filtersForm.isResolveHostnames() && destHostName == null) {
      new Thread(() -> {
        threadsInProgress.incrementAndGet();
        var resolvedHostname = ipHeader.getDstAddr().getHostName();
        resolvedHostNames.put(String.valueOf(ipHeader.getDstAddr()), resolvedHostname);
        packet.setDestinationAddress(new InternetAddress(
          ipHeader.getDstAddr(), resolvedHostname, ipHeader.getDstAddr()));
        threadsInProgress.decrementAndGet();
      }).start();
    }
    var srcHostName = resolvedHostNames.get(String.valueOf(ipHeader.getSrcAddr()));
    var sourceAddress = new InternetAddress(
      ipHeader.getSrcAddr(), srcHostName, ipHeader.getSrcAddr());
    packet.setSourceAddress(sourceAddress);
    if (filtersForm.isResolveHostnames() && srcHostName == null) {
      new Thread(() -> {
        threadsInProgress.incrementAndGet();
        var resolvedHostname = ipHeader.getSrcAddr().getHostName();
        resolvedHostNames.put(String.valueOf(ipHeader.getSrcAddr()), resolvedHostname);
        packet.setSourceAddress(
          new InternetAddress(ipHeader.getDstAddr(), resolvedHostname, ipHeader.getSrcAddr()));
        threadsInProgress.decrementAndGet();
        LOGGER.debug("thread count %s".formatted(threadsInProgress.get()));
      }).start();
      LOGGER.debug("thread count, on easytcp.main thread %s".formatted(threadsInProgress.get()));
    }
  }
}
