package easytcp.model.application;

import easytcp.model.TcpStrategyDetection;
import easytcp.model.packet.TCPConnection;
import org.apache.logging.log4j.util.Strings;
import org.pcap4j.core.PcapNetworkInterface;

public class FiltersForm {
  private static FiltersForm filtersForm;
  private PcapNetworkInterface selectedInterface;
  private boolean showIpv4;
  private boolean showIpv6;
  private boolean resolveHostnames;
  private boolean fullConnectionOnly;
  private boolean scrollDiagram;
  private boolean showAckAndSeqNumbers;
  private boolean showHeaderFlags;
  private boolean showWindowSize;
  private boolean showLength;
  private boolean showTcpOptions;
  private boolean showTcpFeatures;
  private boolean showGeneralInformation;
  private String portRangeSelected;
  private String hostSelected;
  private TCPConnection selectedConnection;
  private TcpStrategyDetection tcpStrategyThreshold;

  public synchronized static FiltersForm getInstance() {
    if (filtersForm == null) {
      filtersForm = new FiltersForm();
      return filtersForm;
    }
    return filtersForm;
  }

  private FiltersForm() {
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
    this.portRangeSelected = null;
    this.hostSelected = null;
    this.selectedConnection = null;
    this.showHeaderFlags = true;
    this.showAckAndSeqNumbers = true;
    this.showLength = true;
    this.showWindowSize = true;
    this.tcpStrategyThreshold = TcpStrategyDetection.BALANCED;
    this.showGeneralInformation = false;
    this.showTcpFeatures = true;
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
    var filterBuilder = new StringBuilder();
    filterBuilder.append("(tcp");
    if (isShowIpv4() && isShowIpv6()) {
      filterBuilder.append(" and (ip or ip6))");
    } else if (isShowIpv6()) {
      filterBuilder.append(" and ip6)");
    } else if (isShowIpv4()) {
      filterBuilder.append(" and ip)");
    } else {
      filterBuilder.append(")");
    }
    if (!Strings.isBlank(getHostSelected())) {
      filterBuilder.append(" and (host %s)"
        .formatted(getHostSelected().replace(" ", "")));
    }
    if (!Strings.isBlank(getPortRangeSelected())) {
      var temp = getPortRangeSelected().replace(" ", "");
      if (temp.contains("-")) {
        filterBuilder.append(" and (portrange %s)".formatted(temp));
      } else {
        filterBuilder.append(" and (dst port %s or src port %s)"
          .formatted(temp, temp));
      }
    }
    return filterBuilder.toString();
  }

  public PcapNetworkInterface getSelectedInterface() {
    return selectedInterface;
  }

  public void setSelectedInterface(PcapNetworkInterface selectedInterface) {
    this.selectedInterface = selectedInterface;
  }

  public TCPConnection getSelectedConnection() {
    return selectedConnection;
  }

  public void setSelectedConnection(TCPConnection selectedConnection) {
    this.selectedConnection = selectedConnection;
  }

  public boolean isFullConnectionOnly() {
    return fullConnectionOnly;
  }

  public void setFullConnectionOnly(boolean fullConnectionOnly) {
    this.fullConnectionOnly = fullConnectionOnly;
  }

  public boolean isScrollDiagram() {
    return scrollDiagram;
  }

  public void setScrollDiagram(boolean scrollDiagram) {
    this.scrollDiagram = scrollDiagram;
  }

  public boolean isShowAckAndSeqNumbers() {
    return showAckAndSeqNumbers;
  }

  public void setShowAckAndSeqNumbers(boolean showAckAndSeqNumbers) {
    this.showAckAndSeqNumbers = showAckAndSeqNumbers;
  }

  public boolean isShowHeaderFlags() {
    return showHeaderFlags;
  }

  public void setShowHeaderFlags(boolean showHeaderFlags) {
    this.showHeaderFlags = showHeaderFlags;
  }

  public boolean isShowWindowSize() {
    return showWindowSize;
  }

  public void setShowWindowSize(boolean showWindowSize) {
    this.showWindowSize = showWindowSize;
  }

  public boolean isShowLength() {
    return showLength;
  }

  public void setShowLength(boolean showLength) {
    this.showLength = showLength;
  }

  public static FiltersForm getFiltersForm() {
    return filtersForm;
  }

  public static void setFiltersForm(FiltersForm filtersForm) {
    FiltersForm.filtersForm = filtersForm;
  }

  public boolean isShowTcpOptions() {
    return showTcpOptions;
  }

  public void setShowTcpOptions(boolean showTcpOptions) {
    this.showTcpOptions = showTcpOptions;
  }

  public TcpStrategyDetection getTcpStrategyThreshold() {
    return tcpStrategyThreshold;
  }

  public void setTcpStrategyThreshold(TcpStrategyDetection tcpStrategyThreshold) {
    this.tcpStrategyThreshold = tcpStrategyThreshold;
  }

  public boolean isShowTcpFeatures() {
    return showTcpFeatures;
  }

  public void setShowTcpFeatures(boolean showTcpFeatures) {
    this.showTcpFeatures = showTcpFeatures;
  }

  public boolean isShowGeneralInformation() {
    return showGeneralInformation;
  }

  public void setShowGeneralInformation(boolean showGeneralInformation) {
    this.showGeneralInformation = showGeneralInformation;
  }
}
