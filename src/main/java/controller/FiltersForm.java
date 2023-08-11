package controller;

public class FiltersForm {
  private boolean ipv4Enabled;
  private boolean ipv6Enabled;
  private boolean resolveHostnames;

  public FiltersForm() {
    // default values
    this.resolveHostnames = false;
    this.ipv4Enabled = true;
    this.ipv6Enabled = false;
  }

  public boolean isIpv4Enabled() {
    return ipv4Enabled;
  }

  public void setIpv4Enabled(boolean ipv4Enabled) {
    this.ipv4Enabled = ipv4Enabled;
  }

  public boolean isIpv6Enabled() {
    return ipv6Enabled;
  }

  public void setIpv6Enabled(boolean ipv6Enabled) {
    this.ipv6Enabled = ipv6Enabled;
  }

  public boolean isResolveHostnames() {
    return resolveHostnames;
  }

  public void setResolveHostnames(boolean resolveHostnames) {
    this.resolveHostnames = resolveHostnames;
  }
}
