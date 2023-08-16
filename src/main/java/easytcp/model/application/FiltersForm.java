package easytcp.model.application;

import org.apache.logging.log4j.util.Strings;
import org.pcap4j.core.PcapNetworkInterface;

public class FiltersForm {
  private PcapNetworkInterface selectedInterface;
  private boolean showIpv4;
  private boolean showIpv6;
  private boolean resolveHostnames;
  private String portRangeSelected;
  private String hostSelected;

  public FiltersForm() {
    restoreDefaults();
  }

  public boolean isShowIpv4() {
    return showIpv4;
  }

  public void setShowIpv4(boolean showIpv4) {
    this.showIpv4 = showIpv4;
  }

  public boolean isShowIpv6() {
    return showIpv6;
  }

  public void setShowIpv6(boolean showIpv6) {
    this.showIpv6 = showIpv6;
  }

  public boolean isResolveHostnames() {
    return resolveHostnames;
  }

  public void setResolveHostnames(boolean resolveHostnames) {
    this.resolveHostnames = resolveHostnames;
  }

  public void restoreDefaults() {
    this.resolveHostnames = false;
    this.showIpv4 = true;
    this.showIpv6 = false;
  }

  public String getPortRangeSelected() {
    return portRangeSelected;
  }

  public void setPortRangeSelected(String portRangeSelected) {
    this.portRangeSelected = portRangeSelected;
  }

  public String getHostSelected() {
    return hostSelected;
  }

  public void setHostSelected(String hostSelected) {
    this.hostSelected = hostSelected;
  }

  public String toBfpExpression() {
    var builder = new StringBuilder();
    var argCount = 0;
    builder.append(" tcp ");
    if (showIpv4 && !showIpv6) {
      builder.append(" ip ");
      argCount++;
    } else if (showIpv6) {
      if (argCount > 0) {
        builder.append(" && ");
      }
      builder.append(" ip6 ");
    }
    if (!Strings.isBlank(hostSelected)) {
      var temp = hostSelected.replace(" ", "");
      if (argCount > 0) {
        builder.append(" && ");
      }
      builder.append(" host %s".formatted(temp));
    }
    if (!Strings.isBlank(portRangeSelected)) {
      if (argCount > 0) {
        builder.append(" && ");
      }
      var temp = portRangeSelected.replace(" ", "");
      if (portRangeSelected.contains("-")) {
        builder.append(" dst portrange %s".formatted(temp));
      } else {
        builder.append(" dst port %s".formatted(temp));
      }
    }
    return builder.toString();
  }

  public PcapNetworkInterface getSelectedInterface() {
    return selectedInterface;
  }

  public void setSelectedInterface(PcapNetworkInterface selectedInterface) {
    this.selectedInterface = selectedInterface;
  }
}
