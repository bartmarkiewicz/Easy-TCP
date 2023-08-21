package easytcp.model;

public enum TcpStrategyDetection {
  LENIENT(2, 100, 0.5),
  BALANCED(3, 150, 0.3),
  STRICT(4, 200, 0.1);

  private final int delayedAckCountThreshold;
  private final int delayedAckCountMsThreshold;
  private final double nagleThresholdModifier;

  TcpStrategyDetection(int delayedAckCountThreshold, int delayedAckCountMsThreshold, double nagleThresholdModifier) {
    this.delayedAckCountThreshold = delayedAckCountThreshold;
    this.delayedAckCountMsThreshold = delayedAckCountMsThreshold;
    this.nagleThresholdModifier = nagleThresholdModifier;
  }

  public int getDelayedAckCountThreshold() {
    return delayedAckCountThreshold;
  }

  public double getNagleThresholdModifier() {
    return nagleThresholdModifier;
  }

  public int getDelayedAckCountMsThreshold() {
    return delayedAckCountMsThreshold;
  }
}
