package easytcp.model;

public enum IPprotocol {
  IPV4("IPv4"),
  IPV6("IPv6");

  private final String displayName;

  IPprotocol(String displayName) {
    this.displayName = displayName;
  }

  public String getDisplayName() {
    return displayName;
  }
}
