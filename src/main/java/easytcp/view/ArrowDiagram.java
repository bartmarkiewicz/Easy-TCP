package easytcp.view;

import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.TCPConnection;
import easytcp.service.PacketDisplayService;
import easytcp.service.ServiceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Line2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;

public class ArrowDiagram extends ScrollableJPanel {
  private static final Logger LOGGER = LoggerFactory.getLogger(ArrowDiagram.class);
  private static final int INITIAL_VERTICAL_POSITION = 100;
  private int currentVerticalPosition;
  private int leftXPos = ApplicationStatus.getStatus().getFrameDimension().width / 10;
  private int arrowDiagramWidth = (ApplicationStatus.getStatus().getFrameDimension().width / 2) - 60;
  private int rightXPos = arrowDiagramWidth - leftXPos;
  private int rightXLabelPos = rightXPos + 5;
  private int leftXLabelPos = leftXPos - 100;
  private final PacketDisplayService packetDisplayService;
  private TCPConnection tempConnection;
  private TCPConnection selectedConnection;

  private JScrollPane scrollPane;
  private FiltersForm filtersForm;
  private static ArrowDiagram arrowDiagram;
  private EasyTCPacket selectedPkt;
  private final AtomicBoolean setViewportToSelectedPkt = new AtomicBoolean(false);
  private Integer selectedPktYPos = 0;

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
  }

  public void setTcpConnection(TCPConnection tcpConnection, FiltersForm filtersForm) {
    this.currentVerticalPosition = INITIAL_VERTICAL_POSITION; //initial position of the start of the arrow
    this.currentHeight = 500;
    this.filtersForm = filtersForm;
    this.selectedConnection = tcpConnection;
    if (tcpConnection == null) {
      this.tempConnection = null;
      scrollPane.getViewport().setViewPosition(new Point(0, 0));
      return;
    } else if (tempConnection != null && !tempConnection.equals(tcpConnection)) {
      scrollPane.getViewport().setViewPosition(new Point(0, 0));
    }
    this.tempConnection = new TCPConnection(tcpConnection); //copies the connection
    tempConnection.setConnectionStatus(ConnectionStatus.UNKNOWN);
    SwingUtilities.invokeLater(() -> {
      repaint();
      revalidate();
    });
  }

  @Override
  protected void paintComponent(Graphics g) {
    super.paintComponent(g);

    leftXPos = ApplicationStatus.getStatus().getFrameDimension().width / 10;
    arrowDiagramWidth = (ApplicationStatus.getStatus().getFrameDimension().width / 2) - 60;
    rightXPos = arrowDiagramWidth - leftXPos;
    rightXLabelPos = rightXPos + 5;
    leftXLabelPos = leftXPos - 100;

    g.setColor(Color.BLACK);
    Graphics2D g2d = (Graphics2D) g;
    g.setFont(new Font(g.getFont().getName(), Font.BOLD, 16));
    if (tempConnection == null) {
      g.drawString("Select a TCP connection to view a diagram", leftXPos + (leftXPos/2), 40);
      g.setFont(new Font(g.getFont().getName(), Font.BOLD, 12));

    } else {
      g.drawString("Connection", leftXPos * 2, 40);
      g.setFont(new Font(g.getFont().getName(), Font.PLAIN, 12));
      g.drawString("Client", 5, 20);
      g.drawString(tempConnection.getHostTwo().getAddressString(), 5, 40);
      g.drawString("Server", rightXPos+5, 20);
      g.drawString(tempConnection.getHost().getAddressString(), rightXPos+5, 40);
    }

    //title bar
    g.fillRect(0, 50, Integer.MAX_VALUE, 1);

    //vertical bars
    g.fillRect(rightXPos, 0, 1, getHeight());
    g.fillRect(leftXPos, 0, 1, getHeight());

    if (tempConnection != null) {
      drawArrows(g2d);
    }
    currentVerticalPosition = INITIAL_VERTICAL_POSITION;

    g.dispose();
  }

  private void drawArrows(Graphics2D g2d) {
    tempConnection.getPacketContainer()
      .getPackets()
      .forEach(pkt -> {
        var leftPoint = new Point();
        var rightPoint = new Point();
        if (selectedPkt != null
          && selectedPkt.equals(pkt)) {
          //highlight selected packet
          g2d.setColor(Color.BLUE);
        }
        if (pkt.getOutgoingPacket()) {
          leftPoint.x = leftXPos;
          leftPoint.y = currentVerticalPosition;
          currentVerticalPosition = currentVerticalPosition + 70;
          rightPoint.x = rightXPos;
          rightPoint.y = currentVerticalPosition;
          g2d.drawString(
            packetDisplayService.getStatusForPacket(pkt, tempConnection).getDisplayText(), leftXLabelPos, currentVerticalPosition-65);
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
          g2d.drawString(packetDisplayService.getStatusForPacket(pkt, tempConnection).getDisplayText(), rightXLabelPos, currentVerticalPosition-65);
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
          scrollPane.getViewport().setViewPosition(new Point(0, currentHeight+100));
        }
        if(selectedPkt != null
          && selectedPkt.equals(pkt)) {
          selectedPktYPos = currentVerticalPosition - 210;
        }
        g2d.setColor(Color.BLACK);
      });
    if (setViewportToSelectedPkt.get()) {
      setViewportToSelectedPkt.set(false);
      scrollPane.getViewport().setViewPosition(new Point(0, selectedPktYPos));
    }

    tempConnection = new TCPConnection(selectedConnection);
    tempConnection.setConnectionStatus(ConnectionStatus.UNKNOWN);
  }

  public void drawArrow(Graphics2D g2d, Point startPoint, Point endPoint) {
    int arrowSize = 16;
    double angle = getRotation(startPoint, endPoint);

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
    return Math.atan2(dy, dx);
  }

  private Point midpoint(Point p1, Point p2) {
    return new Point((int) ((p1.x + p2.x)/2.0), (int) ((p1.y + p2.y)/2.0));
  }

  public void setFilters(FiltersForm filtersForm) {
    this.filtersForm = filtersForm;
  }

  public void setSelectedPacket(EasyTCPacket pkt) {
    this.selectedPkt = pkt;

    if (pkt != null) {
      var packets = pkt.getTcpConnection().getPacketContainer().getPackets();
      var packetLocY = INITIAL_VERTICAL_POSITION - 70;
      for (EasyTCPacket currentPacket : packets) {
        if (currentPacket.equals(selectedPkt)) {
          setViewportToSelectedPkt.set(true);
          this.selectedPktYPos = packetLocY;
        }
        packetLocY += 140;
      }
    }

    revalidate();
    repaint();
  }

  public void saveDiagram(String fileName) {
    var bi = new BufferedImage(this.getSize().width, this.getSize().height, BufferedImage.TYPE_INT_ARGB);
    Graphics imageG = bi.createGraphics();
    this.paint(imageG);  //this == JComponent
    imageG.dispose();
    try{
      ImageIO.write(bi,"png", new File("%s.png".formatted(fileName)));
    } catch (Exception e) {
      LOGGER.error("Error saving diagram png");
    }
  }

  @Override
  public Dimension getPreferredSize() {
    return new Dimension(arrowDiagramWidth, currentHeight);
  }
}
