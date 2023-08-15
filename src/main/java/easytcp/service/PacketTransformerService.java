package easytcp.service;

import easytcp.model.*;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.IpVersion;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class PacketTransformerService {
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
    setTcpConnection(easyTcpPacket, captureData.getTcpConnectionMap(), filtersForm);
    easyTcpPacket.setTimestamp(timestamp);
    easyTcpPacket.setSequenceNumber(tcpHeader.getSequenceNumber());
    easyTcpPacket.setWindowSize(tcpHeader.getWindowAsInt());
    easyTcpPacket.setDataPayloadLength(tcpPacket.getRawData().length);

    easyTcpPacket.setTcpOptions(tcpHeader.getOptions());
    easyTcpPacket.setHeaderPayloadLength(tcpHeader.length());

    return easyTcpPacket;
  }

  private void setTcpConnection(EasyTCPacket easyTcpPacket,
                                HashMap<InternetAddress, TCPConnection> tcpConnectionHashMap,
                                FiltersForm filtersForm) {
    var interfaceAddresses = filtersForm.getSelectedInterface() != null
      ? filtersForm.getSelectedInterface().getAddresses().stream()
      .map(PcapAddress::getAddress).toList()
      : List.of();
    InternetAddress addressOfConnection;
    TCPConnection tcpConnection;
    if (interfaceAddresses.contains(easyTcpPacket.getDestinationAddress())) {
      addressOfConnection = new InternetAddress(easyTcpPacket.getSourceAddress().getPcap4jAddress());
      tcpConnection = tcpConnectionHashMap.getOrDefault(addressOfConnection, new TCPConnection());
      tcpConnection.setHost(addressOfConnection);
      tcpConnection.setHostTwo(new InternetAddress(easyTcpPacket.getDestinationAddress().getPcap4jAddress()));
    } else {
      addressOfConnection = new InternetAddress(easyTcpPacket.getDestinationAddress().getPcap4jAddress());
      tcpConnection = tcpConnectionHashMap.getOrDefault(addressOfConnection, new TCPConnection());
      tcpConnection.setHost(addressOfConnection);
      tcpConnection.setHostTwo(new InternetAddress(easyTcpPacket.getSourceAddress().getPcap4jAddress()));
    }
    tcpConnection.getPacketList().add(easyTcpPacket);

    if (easyTcpPacket.getTcpFlags().get(TCPFlag.SYN) && easyTcpPacket.getTcpFlags().get(TCPFlag.ACK)) {
      tcpConnection.setConnectionStatus(ConnectionStatus.SYN_RECEIVED);
    } else if (easyTcpPacket.getTcpFlags().get(TCPFlag.SYN)) {
      tcpConnection.setConnectionStatus(ConnectionStatus.SYN_SENT);
      tcpConnectionHashMap.put(easyTcpPacket.getSourceAddress(), tcpConnection);
    }
    //initiator of the connection should be the key to the hashmap
//
//    tcpConnection.setHostTwo(new InternetAddress());
//    if (tcpConnection == null) {
//
//    }
//
//
    easyTcpPacket.setTcpConnection(tcpConnection);
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
        System.out.println("thread count %s".formatted(threadsInProgress.get()));
      }).start();
      System.out.println("thread count, on easytcp.main thread %s".formatted(threadsInProgress.get()));
    }
  }
}
