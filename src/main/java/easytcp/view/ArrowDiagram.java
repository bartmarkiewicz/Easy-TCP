package easytcp.view;

import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.TCPConnection;
import easytcp.service.PacketDisplayService;
import easytcp.service.ServiceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Line2D;

public class ArrowDiagram extends JPanel implements Scrollable {
  private static final Logger LOGGER = LoggerFactory.getLogger(ArrowDiagram.class);
  private static final int COMPONENT_WIDTH = 675;
  private static final int INITIAL_VERTICAL_POSITION = 100;
  private int maxUnitIncrement = 3;
  private int currentVerticalPosition;
  private int currentHeight;
  private final int leftXPos = 110;
  private final int rightXPos = COMPONENT_WIDTH - 110;
  private final int rightXLabelPos = rightXPos + 5;
  private final int leftXLabelPos = 15;
  private final PacketDisplayService packetDisplayService;
  private TCPConnection selectedConnection;
  private JScrollPane scrollPane;
  private FiltersForm filtersForm;
  private int horizontalOffset;
  private static ArrowDiagram arrowDiagram;
  private EasyTCPacket selectedPkt;

  public static ArrowDiagram getInstance() {
    if (arrowDiagram == null) {
      arrowDiagram = new ArrowDiagram();
      return arrowDiagram;
    }
    return arrowDiagram;
  }

  public void setScrollPane(JScrollPane scrollPane) {
    this.scrollPane = scrollPane;
  }

  private ArrowDiagram() {
    super(true);
    this.packetDisplayService = ServiceProvider.getInstance().getPacketDisplayService();
    this.currentVerticalPosition = INITIAL_VERTICAL_POSITION; //initial position of the start of the arrow
    currentHeight = 500;
    horizontalOffset = -30;
  }

  public void setTcpConnection(TCPConnection tcpConnection, FiltersForm filtersForm) {
    this.currentVerticalPosition = INITIAL_VERTICAL_POSITION; //initial position of the start of the arrow
    this.currentHeight = 500;
    this.filtersForm = filtersForm;
    if (tcpConnection == null) {
      this.selectedConnection = null;
      scrollPane.getViewport().setViewPosition(new Point(0, 0));
      return;
    }
    this.selectedConnection = new TCPConnection(tcpConnection); //copies the connection
    selectedConnection.setConnectionStatus(ConnectionStatus.CLOSED);
  }

  @Override
  protected void paintComponent(Graphics g) {
    super.paintComponent(g);

    g.setColor(Color.BLACK);
    Graphics2D g2d = (Graphics2D) g;
    g.setFont(new Font(g.getFont().getName(), Font.BOLD, 16));
    if (selectedConnection == null) {
      g.drawString("Select a TCP connection to view a diagram", 115, 40);
      g.setFont(new Font(g.getFont().getName(), Font.BOLD, 12));

    } else {
      g.drawString("Connection", 115, 40);
      g.setFont(new Font(g.getFont().getName(), Font.PLAIN, 12));
      g.drawString("Client", 5, 20);
      g.drawString(selectedConnection.getHostTwo().getAddressString(), 5, 40);
      g.drawString("Server", rightXPos+5, 20);
      g.drawString(selectedConnection.getHost().getAddressString(), rightXPos+5, 40);
    }

    //title bar
    g.fillRect(0, 50, Integer.MAX_VALUE, 1);

    //vertical bars
    g.fillRect(rightXPos, 0, 1, getHeight());
    g.fillRect(leftXPos, 0, 1, getHeight());

    if (selectedConnection != null) {
      drawArrows(g2d);
    }
    currentVerticalPosition = INITIAL_VERTICAL_POSITION;
    g.dispose();
  }

  private void drawArrows(Graphics2D g2d) {
    selectedConnection.getPacketContainer()
      .getPackets()
      .forEach(pkt -> {
        var leftPoint = new Point();
        var rightPoint = new Point();

        if (pkt.getOutgoingPacket()) {
          leftPoint.x = leftXPos;
          leftPoint.y = currentVerticalPosition;
          currentVerticalPosition = currentVerticalPosition + 70;
          rightPoint.x = rightXPos;
          rightPoint.y = currentVerticalPosition;
          g2d.drawString(
            packetDisplayService.getStatusLabelForPacket(pkt, selectedConnection), leftXLabelPos, currentVerticalPosition-65);
          g2d.drawString(packetDisplayService.getSegmentLabel(pkt), leftXLabelPos, currentVerticalPosition-76);
          g2d.drawString(
            packetDisplayService.getConnectionTimestampForPacket(pkt), leftXLabelPos-10, currentVerticalPosition-90);

          drawArrow(g2d, leftPoint, rightPoint);
          currentVerticalPosition = currentVerticalPosition + 70;
          var midpoint = midpoint(leftPoint, rightPoint);
          g2d.setFont(new Font(g2d.getFont().getFontName(), Font.PLAIN, 11));
          var lineLabel = packetDisplayService.getTcpFlagsForPacket(pkt, filtersForm);
          var affineTransform = new AffineTransform();
          affineTransform.rotate(0.15);
          var defaultFont = g2d.getFont();
          var font = new Font(g2d.getFont().getFontName(), Font.PLAIN, 12).deriveFont(affineTransform);
          g2d.setFont(font);
          var tcpOptionsAndWinSize = packetDisplayService.getTcpOptionsForPacket(pkt, filtersForm);
          if (tcpOptionsAndWinSize.length() < 30) {
            g2d.drawString(tcpOptionsAndWinSize, midpoint.x - 80, midpoint.y + 10);
          } else {
            g2d.drawString(tcpOptionsAndWinSize, midpoint.x - 150, midpoint.y);
          }
          g2d.drawString(lineLabel, midpoint.x-80, midpoint.y-20);
          g2d.setFont(defaultFont);
        } else {
          leftPoint.x = leftXPos;
          rightPoint.y = currentVerticalPosition;
          currentVerticalPosition = currentVerticalPosition + 70;
          leftPoint.y = currentVerticalPosition;
          rightPoint.x = rightXPos;
          g2d.drawString(packetDisplayService.getStatusLabelForPacket(pkt, selectedConnection), rightXLabelPos, currentVerticalPosition-65);
          g2d.drawString(packetDisplayService.getSegmentLabel(pkt), rightXLabelPos, currentVerticalPosition-76);
          g2d.drawString(
            packetDisplayService.getConnectionTimestampForPacket(pkt), rightXLabelPos, currentVerticalPosition-90);

          drawArrow(g2d, rightPoint, leftPoint);
          currentVerticalPosition = currentVerticalPosition + 70;
          var midpoint = midpoint(leftPoint, rightPoint);
          var tempFont = g2d.getFont();
          var affineTransform = new AffineTransform();
          affineTransform.rotate(-0.15);
          g2d.setFont(new Font(g2d.getFont().getFontName(), Font.PLAIN, 12).deriveFont(affineTransform));
          var lineLabel = packetDisplayService.getTcpFlagsForPacket(pkt, filtersForm);
          var tcpOptionsAndWinSize = packetDisplayService.getTcpOptionsForPacket(pkt, filtersForm);
          g2d.drawString(lineLabel, midpoint.x-80, midpoint.y);
          if (tcpOptionsAndWinSize.length() < 30) {
            g2d.drawString(tcpOptionsAndWinSize, midpoint.x - 70, midpoint.y + 30);
          } else {
            g2d.drawString(tcpOptionsAndWinSize, midpoint.x - 150, midpoint.y + 40);
          }
          g2d.setFont(tempFont);
        }
        if (currentVerticalPosition >= currentHeight) {
          currentHeight += 100;
          if (scrollPane != null && filtersForm.isScrollDiagram()) {
            scrollPane.getViewport().setViewPosition(new Point(0, currentHeight+100));
          }
        }
      });
    selectedConnection.setConnectionStatus(ConnectionStatus.CLOSED);
  }

  public void drawArrow(Graphics2D g2d, Point startPoint, Point endPoint) {
    int arrowSize = 16;
    var angle = getRotation(startPoint, endPoint);

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

  private Double getRotation(Point startPoint, Point endPoint) {
    var dx = endPoint.getX() - startPoint.getX();
    var dy = endPoint.getY() - startPoint.getY();
    var angle = Math.atan2(dy, dx);
    return angle;
  }

  private Point midpoint(Point p1, Point p2) {
    return new Point((int) ((p1.x + p2.x)/2.0), (int) ((p1.y + p2.y)/2.0));
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

  public void setFilters(FiltersForm filtersForm) {
    this.filtersForm = filtersForm;
  }

  public void setSelectedPacket(EasyTCPacket pkt) {
    this.selectedPkt = pkt;
    var packets = pkt.getTcpConnection().getPacketContainer().getPackets();
    var packetLocY = INITIAL_VERTICAL_POSITION-40;
    for (EasyTCPacket currentPacket : packets) {
      if (selectedPkt.getAckNumber().equals(currentPacket.getAckNumber())
        && selectedPkt.getSequenceNumber().equals(currentPacket.getSequenceNumber())) {
        scrollPane.getViewport().setViewPosition(new Point(0, packetLocY));
      }
      packetLocY += 80;
    }

    repaint();
    revalidate();
  }
}
