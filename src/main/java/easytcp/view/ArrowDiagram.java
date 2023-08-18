package easytcp.view;

import easytcp.model.packet.TCPConnection;
import easytcp.service.PacketDisplayService;
import easytcp.service.ServiceProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.Line2D;

public class ArrowDiagram extends JPanel implements Scrollable {
  private static final int COMPONENT_WIDTH = 675;
  private static final int INITIAL_VERTICAL_POSITION = 100;
  private int maxUnitIncrement = 3;
  private int currentVerticalPosition;
  private int currentHeight;
  private final int leftXPos = 110;
  private final int rightXPos = COMPONENT_WIDTH - 110;
  private final int rightXLabelPos = rightXPos + 5;
  private final int leftXLabelPos = 5;
  private final PacketDisplayService packetDisplayService;
  private TCPConnection selectedConnection;

  private static ArrowDiagram arrowDiagram;

  public static ArrowDiagram getInstance() {
    if (arrowDiagram == null) {
      arrowDiagram = new ArrowDiagram();
      return arrowDiagram;
    }
    return arrowDiagram;
  }

  private ArrowDiagram() {
    super();
//    this.setVerticalScrollBarPolicy(VERTICAL_SCROLLBAR_ALWAYS);
    this.packetDisplayService = ServiceProvider.getInstance().getPacketDisplayService();
    this.currentVerticalPosition = INITIAL_VERTICAL_POSITION; //initial position of the start of the arrow
    currentHeight = 900;
  }

  public void setTcpConnection(TCPConnection tcpConnection) {
    this.selectedConnection = tcpConnection;
    this.currentVerticalPosition = INITIAL_VERTICAL_POSITION; //initial position of the start of the arrow
    this.repaint();
    this.revalidate();
  }

  @Override
  protected void paintComponent(Graphics g) {
    super.paintComponent(g);

    g.setColor(Color.BLACK);
    Graphics2D g2d = (Graphics2D) g;
    g.setFont(new Font(g.getFont().getName(), Font.BOLD, 16));
    if (selectedConnection == null) {
      g.drawString("Select a TCP connection to see a diagram", 115, 40);
      g.setFont(new Font(g.getFont().getName(), Font.BOLD, 12));

    } else {
      g.drawString("Connection", 115, 40);
      g.setFont(new Font(g.getFont().getName(), Font.PLAIN, 12));
      g.drawString("Client %s".formatted(selectedConnection.getHost().getAddressString()), 5, 40);
      g.drawString("Server %s".formatted(selectedConnection.getHostTwo().getAddressString()), rightXPos+5, 40);
    }

    //title bar
    g.fillRect(0, 50, getWidth(), 1);

    //vertical bars
    g.fillRect(rightXPos, 0, 1, getHeight());
    g.fillRect(leftXPos, 0, 1, getHeight());

    if (selectedConnection != null) {
      selectedConnection.getPacketContainer()
        .getPackets()
        .forEach(pkt -> {
          var leftPoint = new Point();
          leftPoint.x = leftXPos;
          leftPoint.y = currentVerticalPosition;
          currentVerticalPosition = currentVerticalPosition + 70;
          var rightPoint = new Point();
          rightPoint.x = rightXPos;
          rightPoint.y = currentVerticalPosition;
          currentVerticalPosition = currentVerticalPosition + 70;

          if (pkt.getOutgoingPacket()) {
            g.drawString(packetDisplayService.getDiagramLabelForPacket(pkt), leftXLabelPos, currentVerticalPosition);

            drawArrow(g2d, leftPoint, rightPoint);
          } else {
            g.drawString(packetDisplayService.getDiagramLabelForPacket(pkt), rightXLabelPos, currentVerticalPosition);
            drawArrow(g2d, rightPoint, leftPoint);
          }

        });

    }
    currentVerticalPosition = INITIAL_VERTICAL_POSITION;
    g.dispose();
  }

  public void drawArrow(Graphics2D g2d, Point startPoint, Point endPoint) {
    int arrowSize = 16;

    var dx = endPoint.getX() - startPoint.getX();
    var dy = endPoint.getY() - startPoint.getY();
    var angle = Math.atan2(dy, dx);

    g2d.setColor(Color.BLACK);
    g2d.setStroke(new BasicStroke(2));
    g2d.draw(new Line2D.Double(startPoint, endPoint));
    var arrowHead = new Polygon();
    arrowHead.addPoint(endPoint.x, endPoint.y);
    arrowHead.addPoint(
      (int) (endPoint.x - arrowSize * Math.cos(angle - Math.PI / 6)),
      (int) (endPoint.y - arrowSize * Math.sin(angle - Math.PI / 6)));
    arrowHead.addPoint(
      (int) (endPoint.x - arrowSize * Math.cos(angle + Math.PI / 6)),
      (int) (endPoint.y - arrowSize * Math.sin(angle + Math.PI / 6)));
    g2d.fill(arrowHead);
  }

  private static Point midpoint(Point p1, Point p2) {
    return new Point((int)((p1.x + p2.x)/2.0),
      (int)((p1.y + p2.y)/2.0));
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
    //Get the current position.
    int currentPosition = 0;
    if (orientation == SwingConstants.HORIZONTAL) {
      currentPosition = visibleRect.x;
    } else {
      currentPosition = visibleRect.y;
    }

    //Return the number of pixels between currentPosition
    //and the nearest tick mark in the indicated direction.
    if (direction < 0) {
      int newPosition = currentPosition -
        (currentPosition / maxUnitIncrement)
          * maxUnitIncrement;
      return (newPosition == 0) ? maxUnitIncrement : newPosition;
    } else {
      return ((currentPosition / maxUnitIncrement) + 1)
        * maxUnitIncrement
        - currentPosition;
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
