package easytcp.view;

import javax.swing.*;
import java.awt.*;

/* A JPanel which can be reliably put inside a scroll pane
 */
public class ScrollableJPanel extends JPanel implements Scrollable {
  private int maxUnitIncrement = 3;
  public int COMPONENT_WIDTH = 675;
  public int currentHeight;

  public ScrollableJPanel(boolean isDoubleBuffered) {
    super(isDoubleBuffered);
  }

  @Override
  public Dimension getPreferredSize() {
    return new Dimension(COMPONENT_WIDTH, currentHeight);
  }

  @Override
  public Dimension getPreferredScrollableViewportSize() {
    return null;
  }

  @Override
  public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
    int currentPosition = 0;
    if (orientation == SwingConstants.HORIZONTAL) {
      currentPosition = visibleRect.x;
    } else {
      currentPosition = visibleRect.y;
    }

    if (direction < 0) {
      int newPosition = currentPosition - (currentPosition / maxUnitIncrement) * maxUnitIncrement;
      return (newPosition == 0) ? maxUnitIncrement : newPosition;
    } else {
      return ((currentPosition / maxUnitIncrement) + 1) * maxUnitIncrement - currentPosition;
    }
  }

  @Override
  public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
    if (orientation == SwingConstants.HORIZONTAL)
      return visibleRect.width - maxUnitIncrement;
    else
      return visibleRect.height - maxUnitIncrement;
  }

  @Override
  public boolean getScrollableTracksViewportWidth() {
    return false;
  }

  @Override
  public boolean getScrollableTracksViewportHeight() {
    return false;
  }
}
