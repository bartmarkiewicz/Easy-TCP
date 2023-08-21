package easytcp.model.application;

import easytcp.model.CaptureStatus;

import java.util.concurrent.atomic.AtomicBoolean;

public class ApplicationStatus {
  private static ApplicationStatus currentApplicationStatus;

  private CaptureStatus methodOfCapture;
  private AtomicBoolean isLiveCapturing = new AtomicBoolean(false);
  private AtomicBoolean isLoading = new AtomicBoolean(false);

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
}
