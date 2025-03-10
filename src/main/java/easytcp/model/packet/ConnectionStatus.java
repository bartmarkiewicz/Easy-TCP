package easytcp.model.packet;

/*Represents the different TCP connection statuses. Some of which are my invention such as 'unknown' or 'rejected'.
 */
public enum ConnectionStatus {
  SYN_SENT("Syn sent"),
  SYN_RECEIVED("Syn received"),
  ESTABLISHED("Established"),
  FIN_WAIT_1("Fin wait 1"),
  FIN_WAIT_2("Fin wait 2"),
  LAST_ACK("Last ack"),
  TIME_WAIT("Time wait"),
  CLOSE_WAIT("Close wait"),
  CLOSED("Closed"),
  CLOSING("Closing"),
  REJECTED("Rejected"),
  UNKNOWN("");
  private final String displayText;

  ConnectionStatus(String displayText) {
    this.displayText = displayText;
  }

  public String getDisplayText() {
    return displayText;
  }
}
