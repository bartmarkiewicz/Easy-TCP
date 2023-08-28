package easytcp.service;

import easytcp.TestUtils;
import easytcp.model.TcpStrategyDetection;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectionDisplayServiceTest {

  private final ConnectionDisplayService connectionDisplayService = new ConnectionDisplayService();

  @ParameterizedTest
  @EnumSource(TcpStrategyDetection.class)
  void getConnectionInformation_whenAllEnabled(TcpStrategyDetection strategyDetection) {
    var filters = FiltersForm.getInstance();
    filters.setShowLength(true);
    filters.setShowAckAndSeqNumbers(true);
    filters.setShowHeaderFlags(true);
    filters.setShowGeneralInformation(true);
    filters.setShowTcpFeatures(true);
    filters.setShowTcpOptions(true);
    filters.setTcpStrategyThreshold(strategyDetection);
    var fullCon = TestUtils.getConnectionWithHandshakeAndFin();
    fullCon.setConnectionStatus(ConnectionStatus.UNKNOWN);
    var result = connectionDisplayService.getConnectionInformation(fullCon);
    if(strategyDetection == TcpStrategyDetection.STRICT
      || strategyDetection == TcpStrategyDetection.BALANCED) {
      assertThat(result).isEqualTo("""
        Connection status:\s
        Packets sent: 3
        Packets received: 4
        Host one: fish.com
        Host two: host.com
        Port one : 80
        Port two : 80
        Bytes sent 80
        Bytes received 2
        Packet flags sent/received
        SYN 1/1
        ACK 2/4
        PSH 1/1
        FIN 1/1
        """);
    } else {
      assertThat(result).isEqualTo("""
        Connection status:\s
        Packets sent: 3
        Packets received: 4
        Host one: fish.com
        Host two: host.com
        Port one : 80
        Port two : 80
        Bytes sent 80
        Bytes received 2
        TCP features on the server\s
        Delayed ack is enabled\s
              
        Packet flags sent/received
        SYN 1/1
        ACK 2/4
        PSH 1/1
        FIN 1/1
        """);
    }
  }

  @ParameterizedTest
  @EnumSource(TcpStrategyDetection.class)
  void getConnectionInformation_whenConWithNagle(TcpStrategyDetection strategyDetection) {
    var filters = FiltersForm.getInstance();
    filters.setShowLength(true);
    filters.setShowHeaderFlags(true);
    filters.setShowGeneralInformation(true);
    filters.setShowTcpFeatures(true);
    filters.setShowTcpOptions(true);
    filters.setTcpStrategyThreshold(strategyDetection);
    var fullCon = TestUtils.getConnectionWithNagle();
    fullCon.setConnectionStatus(ConnectionStatus.UNKNOWN);
    var result = connectionDisplayService.getConnectionInformation(fullCon);
    if(strategyDetection == TcpStrategyDetection.STRICT) {
      assertThat(result).isEqualTo("""
        Connection status:\s
        Packets sent: 4
        Packets received: 3
        Host one: fish.com
        Host two: host.com
        Port one : 80
        Port two : 80
        Bytes sent 80
        Bytes received 60
        TCP features on the client\s
        Nagle's algorithm is enabled\s
                
        TCP features on the server\s
        Nagle's algorithm is enabled\s
        
        Client TCP options
        MSS - 20
        Window scale - 2
                
        Server TCP options
        MSS - 20
        Window scale - 1
                
        Packet flags sent/received
        SYN 1/1
        ACK 3/3
        """);
    } else {
      assertThat(result).isEqualTo("""
        Connection status:\s
        Packets sent: 4
        Packets received: 3
        Host one: fish.com
        Host two: host.com
        Port one : 80
        Port two : 80
        Bytes sent 80
        Bytes received 60
        TCP features on the client\s
        Nagle's algorithm is enabled\s
        
        TCP features on the server\s
        Nagle's algorithm is enabled\s
              
        Client TCP options
        MSS - 20
        Window scale - 2
        
        Server TCP options
        MSS - 20
        Window scale - 1

        Packet flags sent/received
        SYN 1/1
        ACK 3/3
        """);
    }
  }

  @ParameterizedTest
  @EnumSource(TcpStrategyDetection.class)
  void getConnectionInformation_whenConWithNagle_whenOnlyFeaturesEnabled(TcpStrategyDetection strategyDetection) {
    var filters = FiltersForm.getInstance();
    filters.setShowLength(false);
    filters.setShowHeaderFlags(false);
    filters.setShowGeneralInformation(false);
    filters.setShowTcpFeatures(true);
    filters.setShowTcpOptions(false);
    filters.setTcpStrategyThreshold(strategyDetection);
    //has nagle on server and client
    var fullCon = TestUtils.getConnectionWithNagle();
    fullCon.setConnectionStatus(ConnectionStatus.LAST_ACK);
    var result = connectionDisplayService.getConnectionInformation(fullCon);
    assertThat(result).isEqualToIgnoringWhitespace("""
      Connection status: Last ack
      TCP features on the client\s
      Nagle's algorithm is enabled\s
              
      TCP features on the server\s
      Nagle's algorithm is enabled\s
      
      """);
  }

  @ParameterizedTest
  @EnumSource(TcpStrategyDetection.class)
  void getConnectionInformation_whenConWithSlowStart_whenOnlyFeaturesEnabled(TcpStrategyDetection strategyDetection) {
    var filters = FiltersForm.getInstance();
    filters.setShowLength(false);
    filters.setShowHeaderFlags(false);
    filters.setShowGeneralInformation(false);
    filters.setShowTcpFeatures(true);
    filters.setShowTcpOptions(false);
    filters.setTcpStrategyThreshold(strategyDetection);
    //slow start on the client
    var fullCon = TestUtils.getConnectionWithSlowStart();
    fullCon.setConnectionStatus(ConnectionStatus.UNKNOWN);
    var result = connectionDisplayService.getConnectionInformation(fullCon);
    if (strategyDetection == TcpStrategyDetection.LENIENT) {
      assertThat(result).isEqualToIgnoringWhitespace("""
      Connection status:
      TCP features on the client
      Delayed ack is enabled
      Slow start is enabled
      """);
  } else {
    assertThat(result).isEqualToIgnoringWhitespace("""
        Connection status:
        TCP features on the client
        Slow start is enabled
        """);
    }
  }
}