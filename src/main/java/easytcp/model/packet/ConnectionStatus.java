package easytcp.model.packet;

public enum ConnectionStatus {
  SYN_SENT,
  SYN_RECEIVED,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  LAST_ACK,
  TIME_WAIT,
  CLOSE_WAIT,
  CLOSED,
  UNKNOWN;
}
