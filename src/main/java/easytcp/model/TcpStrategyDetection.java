package easytcp.model;

/* Enum encapsulating the different values for the TCP strategy detection thresholds,
 * this is to set the sensitivity of detection algorithms which cannot be 100% accurate from a tcpdump.
 */
public enum TcpStrategyDetection {
  LENIENT(2, 100, 0.7, 0.75),
  BALANCED(3, 150, 0.5, 0.85),
  STRICT(4, 200, 0.3, 0.95);

  private final int delayedAckCountThreshold;
  private final int delayedAckCountMsThreshold;
  private final double slowStartThreshold;
  private final double nagleThresholdModifier;

  TcpStrategyDetection(int delayedAckCountThreshold, int delayedAckCountMsThreshold, double slowStartThreshold, double nagleThresholdModifier) {
    this.delayedAckCountThreshold = delayedAckCountThreshold;
    this.delayedAckCountMsThreshold = delayedAckCountMsThreshold;
    this.slowStartThreshold = slowStartThreshold;
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

  public double getSlowStartThreshold() {
    return slowStartThreshold;
  }
}
