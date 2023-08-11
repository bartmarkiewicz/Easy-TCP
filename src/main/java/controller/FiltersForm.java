package controller;

public class FiltersForm {
  private boolean showIpv4;
  private boolean showIpv6;
  private boolean resolveHostnames;
  private Boolean readingFromFile;

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
    this.showIpv6 = true;
  }

  public Boolean isReadingFromFile() {
    return readingFromFile;
  }

  public void setReadingFromFile(Boolean readingFromFile) {
    this.readingFromFile = readingFromFile;
  }
}
