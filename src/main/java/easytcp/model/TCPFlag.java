package easytcp.model;

public enum TCPFlag {
  URG("U"),
  ACK("."),
  PSH("P"),
  RST("R"),
  SYN("S"),
  FIN("F");

  private final String displayName;

  TCPFlag(String displayName) {
    this.displayName = displayName;
  }

  public String getDisplayName() {
    return displayName;
  }
}
