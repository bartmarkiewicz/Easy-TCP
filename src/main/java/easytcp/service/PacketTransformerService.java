package easytcp.service;

import easytcp.model.*;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.*;
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
    setAddressesAndHostnames(
      ipHeader, tcpHeader, easyTcpPacket, captureData.getResolvedHostnames(), filtersForm);
    easyTcpPacket.setTimestamp(timestamp);
    easyTcpPacket.setSequenceNumber(Long.valueOf(tcpHeader.getSequenceNumber()));
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
//      addressOfConnection = new InternetAddress(
//        easyTcpPacket.getSourceAddress().getPcap4jAddress(),
//        easyTcpPacket.getSourceAddress().getPort());
      addressOfConnection = easyTcpPacket.getSourceAddress();
      tcpConnection = tcpConnectionHashMap.getOrDefault(addressOfConnection, new TCPConnection());
      tcpConnection.setHost(addressOfConnection);
      tcpConnection.setHostTwo(easyTcpPacket.getDestinationAddress());
      easyTcpPacket.setOutgoingPacket(true);
//      tcpConnection.setHostTwo(new InternetAddress(easyTcpPacket.getDestinationAddress().getPcap4jAddress(), easyTcpPacket.getDestinationAddress().getPort()));
    } else {
//      addressOfConnection = new InternetAddress(easyTcpPacket.getDestinationAddress().getPcap4jAddress());
      addressOfConnection = easyTcpPacket.getDestinationAddress();
      tcpConnection = tcpConnectionHashMap.getOrDefault(addressOfConnection, new TCPConnection());
      easyTcpPacket.setOutgoingPacket(false);
      tcpConnection.setHost(addressOfConnection);
      tcpConnection.setHostTwo(easyTcpPacket.getSourceAddress());
    }

    determineStatusOfConnection(tcpConnection, easyTcpPacket, filtersForm);


    tcpConnectionHashMap.put(addressOfConnection, tcpConnection);
    easyTcpPacket.setTcpConnection(tcpConnection);
  }

  private void determineStatusOfConnection(
    TCPConnection tcpConnection, EasyTCPacket easyTcpPacket,
    FiltersForm filtersForm) {
    //todo sort by timestamp, determine status of connection by latest packet
    tcpConnection.getPacketContainer().addPacketToContainer(easyTcpPacket);
    var packetList = tcpConnection.getPacketContainer().getPackets();
    var i = 1;
    var latestPacket = packetList.get(packetList.size() - i);
    while (latestPacket.getTcpFlags().get(TCPFlag.RST)) {
      i++;
      if (i > packetList.size()) {
        tcpConnection.setConnectionStatus(ConnectionStatus.UNKNOWN);
        LOGGER.info("Connection not established, only RST packets");
        return;
      }
      latestPacket = packetList.get(packetList.size() - i);
    }

    var packetBeingAcked =
      tcpConnection.getPacketContainer()
        .findPacketWithSeqNumber(latestPacket.getSequenceNumber());
    var currentPacketFlags = latestPacket.getTcpFlags();
    //todo maybe add checks for current status
//    easyTcpPacket = latestPacket;
    if (tcpConnection.getConnectionStatus() == null) {
      tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
    }
    switch (tcpConnection.getConnectionStatus()) {
      case CLOSED -> {
        //determine initial connection status
        if (currentPacketFlags.get(TCPFlag.SYN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
        } else if (currentPacketFlags.get(TCPFlag.PSH)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.PSH)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
        } else if (currentPacketFlags.get(TCPFlag.FIN) || currentPacketFlags.get(TCPFlag.ACK)) {
            tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
        } else if (currentPacketFlags.get(TCPFlag.SYN)
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
        }
      }
      case SYN_SENT -> {
        LOGGER.debug("SYN SENT");
        if (currentPacketFlags.get(TCPFlag.SYN)
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
        } else if (currentPacketFlags.get(TCPFlag.SYN)) {
          // simultaneous open
          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
        } else if (currentPacketFlags.get(TCPFlag.ACK)
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
          && currentPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSE_WAIT);
        } else if (latestPacket.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_1);
        } else if (latestPacket.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSE_WAIT);
        }
      }
      case CLOSE_WAIT -> {
        LOGGER.debug("close wait");

        if (latestPacket.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.LAST_ACK);
        }
      }
      case LAST_ACK -> {
        LOGGER.debug("last ack");

        if (!latestPacket.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED);
        }
      }
      case FIN_WAIT_1 -> {
        LOGGER.debug("fin wait");

        if (latestPacket.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)
          && !packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.CLOSING);
        } else if (latestPacket.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.TIME_WAIT);
        } else if (!latestPacket.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_2);
        }
      }
      case FIN_WAIT_2 -> {
        LOGGER.debug("fin wait 2");

        if (latestPacket.getOutgoingPacket()
          && currentPacketFlags.get(TCPFlag.ACK)
          && packetBeingAcked.isPresent()
          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN)) {
          tcpConnection.setConnectionStatus(ConnectionStatus.TIME_WAIT);
        }
      }
      case TIME_WAIT -> {
        LOGGER.debug("time wait");

      }
    }
  }


//        if (!easyTcpPacket.getOutgoingPacket() && currentPacketFlags.get(TCPFlag.SYN)) {
//          // simultaneous open
//          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
//        } else if (easyTcpPacket.getOutgoingPacket()
//          && currentPacketFlags.get(TCPFlag.SYN)
//          && currentPacketFlags.get(TCPFlag.ACK)
//          && packetBeingAcked.isPresent()
//          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
//          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
//        } else if (currentPacketFlags.get(TCPFlag.ACK)
//          && packetBeingAcked.isPresent()
//          && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)) {
//          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
//        }
//      }
//    }

//    if (tcpConnection.getConnectionStatus() == null || tcpConnection.getConnectionStatus() == ConnectionStatus.UNKNOWN) {
//      if (easyTcpPacket.getTcpFlags().get(TCPFlag.SYN)
//        && !easyTcpPacket.getTcpFlags().get(TCPFlag.ACK)) {
//        //attempting to start connection syn sent
//        tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
//      } else if (easyTcpPacket.getTcpFlags().get(TCPFlag.SYN)
//        && easyTcpPacket.getTcpFlags().get(TCPFlag.ACK)
//        && packetBeingAcked.isPresent()) {
//        tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
//      } else if (packetBeingAcked.isPresent()
//        && packetBeingAcked.get().getTcpFlags().get(TCPFlag.SYN)
//        && easyTcpPacket.getTcpFlags().get(TCPFlag.ACK)) {
//        tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
//      } else if (packetBeingAcked.isPresent()
//        && packetBeingAcked.get().getTcpFlags().get(TCPFlag.PSH)
//        && easyTcpPacket.getTcpFlags().get(TCPFlag.ACK)
//        && easyTcpPacket.getTcpFlags().get(TCPFlag.PSH)) {
//        //likely established
//        if (!filtersForm.isFullConnectionOnly()) {
//          tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
//        }
//      } else if (easyTcpPacket.getTcpFlags().get(TCPFlag.FIN)
//        && (packetBeingAcked.isEmpty()
//        || !packetBeingAcked.get().getTcpFlags().get(TCPFlag.FIN))) {
//        // beginning of close
//      }
//    }

//    if (latestPacket.getOutgoingPacket()
//      && latestPacket.getTcpFlags().get(TCPFlag.SYN)
//      && latestPacket.getTcpFlags().get(TCPFlag.ACK)) {
//      tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
//      LOGGER.info("Syn received, sending syn ack to complete TCP handshake between %s, %s"
//        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));
//    } else if (latestPacket.getOutgoingPacket() && latestPacket.getTcpFlags().get(TCPFlag.SYN)) {
//      tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
//      LOGGER.info("Started a tcp handshake between %s and %s"
//        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));
//    } else if (!latestPacket.getOutgoingPacket() //if incoming packet with SYN and an ACK for the syn
//      && latestPacket.getTcpFlags().get(TCPFlag.SYN)
//      && latestPacket.getTcpFlags().get(TCPFlag.ACK)) {
//      tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED);
//      LOGGER.info("Established TCP connection between %s and %s"
//        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));
//    } else if (latestPacket.getOutgoingPacket() && latestPacket.getTcpFlags().get(TCPFlag.FIN)) {
//      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status FIN_WAIT_1"
//        .formatted(
//          tcpConnection.getConnectionStatus(),
//          tcpConnection.getHost().getAddressString(),
//          tcpConnection.getHostTwo().getAddressString()));
//      tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_1); // active close
//    } else if (!latestPacket.getOutgoingPacket()
//      && latestPacket.getTcpFlags().get(TCPFlag.FIN)
//      && latestPacket.getTcpFlags().get(TCPFlag.ACK)) {
//      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status CLOSE WAIT"
//        .formatted(
//          tcpConnection.getConnectionStatus(),
//          tcpConnection.getHost().getAddressString(),
//          tcpConnection.getHostTwo().getAddressString()));
//      tcpConnection.setConnectionStatus(ConnectionStatus.CLOSE_WAIT); // passive close
//    } else if (!latestPacket.getOutgoingPacket()
//      && tcpConnection.getConnectionStatus() == ConnectionStatus.CLOSE_WAIT
//      && latestPacket.getTcpFlags().get(TCPFlag.ACK)
//      && !latestPacket.getTcpFlags().get(TCPFlag.FIN)) {
//      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status FIN_WAIT_2"
//        .formatted(
//          tcpConnection.getConnectionStatus(),
//          tcpConnection.getHost().getAddressString(),
//          tcpConnection.getHostTwo().getAddressString()));
//      tcpConnection.setConnectionStatus(ConnectionStatus.FIN_WAIT_2); // passive close
//    } else if (!latestPacket.getOutgoingPacket()
//      && latestPacket.getTcpFlags().get(TCPFlag.FIN)) {
//      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status TIME_WAIT"
//        .formatted(
//          tcpConnection.getConnectionStatus(),
//          tcpConnection.getHost().getAddressString(),
//          tcpConnection.getHostTwo().getAddressString()));
//      tcpConnection.setConnectionStatus(ConnectionStatus.TIME_WAIT); // passive close
//    } else if (latestPacket.getOutgoingPacket()
//      && latestPacket.getTcpFlags().get(TCPFlag.ACK)
//      && tcpConnection.getConnectionStatus() == ConnectionStatus.TIME_WAIT) {
//      LOGGER.info("Current TCP status %s attempting to orderly close connection between %s and %s, new status CLOSED"
//        .formatted(
//          tcpConnection.getConnectionStatus(),
//          tcpConnection.getHost().getAddressString(),
//          tcpConnection.getHostTwo().getAddressString()));
//      tcpConnection.setConnectionStatus(ConnectionStatus.CLOSED); // passive close
//    } else if (latestPacket.getTcpFlags().get(TCPFlag.PSH)
//      && latestPacket.getTcpFlags().get(TCPFlag.ACK)
//      && !latestPacket.getTcpFlags().get(TCPFlag.RST)){
////      LOGGER.info("Connections probably is live between %s and %s"
////        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));
//      tcpConnection.setConnectionStatus(ConnectionStatus.ESTABLISHED); //probably established
//    } else if (latestPacket.getTcpFlags().get(TCPFlag.RST)) {
//      LOGGER.info("Connection unexpected, disorderly close between %s and %s"
//        .formatted(tcpConnection.getHost().getAddressString(), tcpConnection.getHostTwo().getAddressString()));
//    }
//    if (tcpConnection.getConnectionStatus() == null) {
//      tcpConnection.setConnectionStatus(ConnectionStatus.UNKNOWN);
//    }
//  }

//  private void setStatusForOutgoingPacket(TCPConnection tcpConnection, EasyTCPacket easyTcpPacket, Optional<EasyTCPacket> packetBeingAcked) {
//    var pktFlags = easyTcpPacket.getTcpFlags();
//    switch (tcpConnection.getConnectionStatus()) {
//      case CLOSED -> {
//        if (pktFlags.get(TCPFlag.SYN)) {
//          tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
//        }
//      }
//      case SYN_SENT -> {
//        if ()
//      }
//    }
//  }

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
        threadsInProgress.incrementAndGet();
        var resolvedHostname = ipHeader.getDstAddr().getHostName();
        resolvedHostNames.put(String.valueOf(ipHeader.getDstAddr()), resolvedHostname);
        packet.setDestinationAddress(new InternetAddress(
          ipHeader.getDstAddr(), resolvedHostname, ipHeader.getDstAddr(), tcpHeader.getDstPort()));
        threadsInProgress.decrementAndGet();
      }).start();
    }
    var srcHostName = resolvedHostNames.get(String.valueOf(ipHeader.getSrcAddr()));
    var sourceAddress = new InternetAddress(
      ipHeader.getSrcAddr(), srcHostName, ipHeader.getSrcAddr(), tcpHeader.getDstPort());
    packet.setSourceAddress(sourceAddress);
    if (filtersForm.isResolveHostnames() && srcHostName == null) {
      new Thread(() -> {
        threadsInProgress.incrementAndGet();
        var resolvedHostname = ipHeader.getSrcAddr().getHostName();
        resolvedHostNames.put(String.valueOf(ipHeader.getSrcAddr()), resolvedHostname);
        packet.setSourceAddress(
          new InternetAddress(ipHeader.getDstAddr(), resolvedHostname, ipHeader.getSrcAddr(), tcpHeader.getSrcPort()));
        threadsInProgress.decrementAndGet();
        LOGGER.debug("thread count %s".formatted(threadsInProgress.get()));
      }).start();
      LOGGER.debug("thread count, on easytcp.main thread %s".formatted(threadsInProgress.get()));
    }
  }
}
