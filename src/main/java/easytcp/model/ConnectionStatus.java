package easytcp.model;

public enum ConnectionStatus {
  SYN_SENT,
  SYN_RECEIVED,
  ESTABLISHED,
  FIN_WAIT,
  CLOSE_WAIT,
  CLOSED
}
