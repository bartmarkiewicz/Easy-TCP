package easytcp.model;

/* Enum encapsulating the different values for the TCP strategy detection thresholds,
 * this is to set the sensitivity of detection algorithms which cannot be 100% accurate from a tcpdump.
 */
public enum TcpStrategyDetection {
  LENIENT(2, 150, 0.7, 0.75, 0.2),
  BALANCED(3, 200, 0.5, 0.85, 0.4),
  STRICT(4, 250, 0.3, 0.95, 0.6);

  private final int delayedAckCountThreshold; // the number of packets received before an ack was sent
  private final int delayedAckCountMsThreshold; //the delayed ack timeout delay, typically set as 200ms
  private final double slowStartThreshold; // Times by which the window size needs to be increased by
  private final double nagleThresholdModifier; //the percent of the MSS a packet payload needs to be for it to be suspected of having buffered the data for nagle
  private final double percentOfPackets; //the percent of eligible packets needing to match the criteria for a strategy to be detected

  TcpStrategyDetection(int delayedAckCountThreshold,
                       int delayedAckCountMsThreshold,
                       double slowStartThreshold,
                       double nagleThresholdModifier,
                       double percentOfPackets) {
    this.delayedAckCountThreshold = delayedAckCountThreshold;
    this.delayedAckCountMsThreshold = delayedAckCountMsThreshold;
    this.slowStartThreshold = slowStartThreshold;
    this.nagleThresholdModifier = nagleThresholdModifier;
    this.percentOfPackets = percentOfPackets;
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

  public double getPercentOfPackets() {
    return percentOfPackets;
  }
}
