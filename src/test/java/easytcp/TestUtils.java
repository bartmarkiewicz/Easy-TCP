package easytcp;

import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.InternetAddress;

import java.net.UnknownHostException;

public class TestUtils {

  public static EasyTCPacket createEasyTcpPacket() {
    var packet = new EasyTCPacket();
    return packet;
  }

  public static InternetAddress createAddress() throws UnknownHostException {
    var internetAddress =
      new InternetAddress("185.2.33.4.5", "fish.com", null, 80);
    return internetAddress;
  }
}
