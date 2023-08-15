package easytcp.model;

public class ApplicationStatus {
  private static ApplicationStatus currentApplicationStatus;

  private CaptureStatus methodOfCapture;
  private boolean isLiveCapturing;
  private boolean isLoading;

  private ApplicationStatus() {
  }

  public static ApplicationStatus getStatus() {
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

  public boolean isLiveCapturing() {
    return isLiveCapturing;
  }

  public void setLiveCapturing(boolean liveCapturing) {
    isLiveCapturing = liveCapturing;
  }

  public boolean isLoading() {
    return isLoading;
  }

  public void setLoading(boolean loading) {
    isLoading = loading;
  }
}
