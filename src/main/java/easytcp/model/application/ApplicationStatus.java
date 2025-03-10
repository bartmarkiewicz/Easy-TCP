package easytcp.model.application;

import easytcp.model.CaptureStatus;

import java.awt.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tracks the current status of EasyTCP
 */
public class ApplicationStatus {
  private static ApplicationStatus currentApplicationStatus;
  private CaptureStatus methodOfCapture;
  private Dimension frameDimension;
  private final AtomicBoolean isLiveCapturing = new AtomicBoolean(false);
  private final AtomicBoolean isLoading = new AtomicBoolean(false);

  private ApplicationStatus() {
  }

  public synchronized static ApplicationStatus getStatus() {
    if (currentApplicationStatus == null) {
      currentApplicationStatus = new ApplicationStatus();
    }
    return currentApplicationStatus;
  }

  public CaptureStatus getMethodOfCapture() {
    return methodOfCapture;
  }

  public void setMethodOfCapture(CaptureStatus methodOfCapture) {
    this.methodOfCapture = methodOfCapture;
  }

  public AtomicBoolean isLiveCapturing() {
    return isLiveCapturing;
  }

  public void setLiveCapturing(boolean liveCapturing) {
    isLiveCapturing.set(liveCapturing);
  }

  public AtomicBoolean isLoading() {
    return isLoading;
  }

  public void setLoading(boolean loading) {
    isLoading.set(loading);
  }

  public Dimension getFrameDimension() {
    return frameDimension;
  }

  public void setFrameDimension(Dimension frameDimension) {
    this.frameDimension = frameDimension;
  }
}
