package easytcp.view;

import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.TCPConnection;
import easytcp.service.ArrowDiagramMouseListener;
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

/* This is the panel which draws the arrows diagram
 */
public class ArrowDiagram extends ScrollableJPanel {
  private static final Logger LOGGER = LoggerFactory.getLogger(ArrowDiagram.class);
  private static final int INITIAL_VERTICAL_POSITION = 100; // the Y axis coordinate of the start of the first arrow
  private int currentVerticalPosition; // the current Y position to which everything is relative
  private int leftXPos = ApplicationStatus.getStatus().getFrameDimension().width / 10; //this is the left X axis coordinate
  private int arrowDiagramWidth = (ApplicationStatus.getStatus().getFrameDimension().width / 2) - 60; // this is the width of the arrows diagram
  private int rightXPos = arrowDiagramWidth - leftXPos;
  private int rightXLabelPos = rightXPos + 5; //this is the X axis position of the right label
  private int leftXLabelPos = leftXPos - 100;
  private final PacketDisplayService packetDisplayService;
  private TCPConnection selectedConnection;

  private JScrollPane scrollPane;
  private FiltersForm filtersForm;
  private static ArrowDiagram arrowDiagram;
  private EasyTCPacket selectedPkt;
  private final AtomicBoolean setViewportToSelectedPkt = new AtomicBoolean(false);
  private Integer selectedPktYPos = 0;
  private ArrowDiagramMouseListener arrowDiagramMouseListener;

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
    this.arrowDiagramMouseListener = new ArrowDiagramMouseListener(this, PacketLog.getPacketLog(
        FiltersForm.getInstance(), ServiceProvider.getInstance()));
    arrowDiagramMouseListener.setSelectedConnection(null);
    this.addMouseListener(arrowDiagramMouseListener);
  }

  /* Sets the TCP connection to be drawn
   */
  public void setTcpConnection(TCPConnection tcpConnection, FiltersForm filtersForm) {
    this.currentVerticalPosition = INITIAL_VERTICAL_POSITION;
    this.currentHeight = 500;
    this.filtersForm = filtersForm;
    if (selectedConnection != null && !selectedConnection.equals(tcpConnection) && !setViewportToSelectedPkt.get()) {
      scrollPane.getViewport().setViewPosition(new Point(0, 0));
    }
    this.selectedConnection = tcpConnection;
    //sets the initial status
    if (selectedConnection != null) {
      selectedConnection.setStatusAsOfPacketTraversal(ConnectionStatus.UNKNOWN);
    }
    arrowDiagramMouseListener.setSelectedConnection(selectedConnection);
    repaint();
    revalidate();
  }

  /* Draws the arrows diagram here
   */
  @Override
  protected void paintComponent(Graphics g) {
    var g2d = (Graphics2D) g;
    super.paintComponent(g2d);

    //Gets the current frame dimensions
    leftXPos = ApplicationStatus.getStatus().getFrameDimension().width / 10;
    arrowDiagramWidth = (ApplicationStatus.getStatus().getFrameDimension().width / 2) - 60;
    rightXPos = arrowDiagramWidth - leftXPos;
    rightXLabelPos = rightXPos + 5;
    leftXLabelPos = leftXPos - 100;

    g2d.setColor(Color.BLACK);
    g2d.setFont(new Font(g2d.getFont().getName(), Font.BOLD, 16));
    //draws the heading
    if (selectedConnection == null) {
      g2d.drawString("Select a TCP connection to view a diagram", leftXPos + (leftXPos/2), 40);
      g2d.setFont(new Font(g2d.getFont().getName(), Font.BOLD, 12));
    } else {
      g2d.drawString("Connection", leftXPos * 2, 40);
      g2d.setFont(new Font(g2d.getFont().getName(), Font.PLAIN, 12));
      g2d.drawString("Client", 5, 20);
      var resolveHostnames = FiltersForm.getInstance().isResolveHostnames();
      g2d.drawString((resolveHostnames
              ? selectedConnection.getConnectionAddresses().addressTwo().getAddressString()
              : selectedConnection.getConnectionAddresses().addressTwo().getAlphanumericalAddress()) +":%s"
              .formatted(selectedConnection.getConnectionAddresses().addressTwo().getPort()) , 5, 40);
      g2d.drawString("Server", rightXPos+5, 20);
      g2d.drawString((resolveHostnames
              ? selectedConnection.getConnectionAddresses().addressOne().getAddressString()
              : selectedConnection.getConnectionAddresses().addressOne().getAlphanumericalAddress()) + ":%s"
              .formatted(selectedConnection.getConnectionAddresses().addressOne().getPort()), rightXPos+5, 40);
    }

    //title bar
    g2d.fillRect(0, 50, Integer.MAX_VALUE, 1);

    //vertical bars
    g2d.fillRect(rightXPos, 0, 1, getHeight());
    g2d.fillRect(leftXPos, 0, 1, getHeight());

    if (selectedConnection != null) {
      //draws the arrows and their labels
      drawArrows(g2d);
    }
    //resets vertical position
    currentVerticalPosition = INITIAL_VERTICAL_POSITION;

    g2d.dispose();
  }

  /*
   * Draws arrows and labels
   */
  private void drawArrows(Graphics2D g2d) {
    selectedConnection.getPacketContainer()
      .getPackets()
      .forEach(pkt -> {
        if (!packetDisplayService.isVisible(pkt, FiltersForm.getInstance())) {
          return;
        }

        var leftPoint = new Point();
        var rightPoint = new Point();
        if (selectedPkt != null
          && selectedPkt.equals(pkt)) {
          //highlight selected packet in blue
          g2d.setColor(Color.BLUE);
        }
        if (pkt.getOutgoingPacket()) {
          // if outgoing the arrow is from left to right
          leftPoint.x = leftXPos;
          leftPoint.y = currentVerticalPosition;
          currentVerticalPosition = currentVerticalPosition + 70;
          rightPoint.x = rightXPos;
          rightPoint.y = currentVerticalPosition;
          var currentStatus = selectedConnection.getStatusAsOfPacketTraversal();
          var nextStatus = packetDisplayService.getStatusForPacket(pkt, selectedConnection);
          if (currentStatus != nextStatus) {
            // if status changed, draws the status label
            g2d.drawString(nextStatus.getDisplayText(), leftXLabelPos, currentVerticalPosition - 65);
          }
          g2d.drawString(packetDisplayService.getSegmentLabel(pkt), leftXLabelPos, currentVerticalPosition-76);
          g2d.drawString(
            packetDisplayService.getConnectionTimestampForPacket(pkt), leftXLabelPos-10, currentVerticalPosition-90);

          drawArrow(g2d, leftPoint, rightPoint);
          currentVerticalPosition = currentVerticalPosition + 70;
          var midpoint = midpoint(leftPoint, rightPoint); //middle of the arrow
          g2d.setFont(new Font(g2d.getFont().getFontName(), Font.PLAIN, 11));
          var lineLabel = packetDisplayService.getTcpFlagsForPacket(pkt, filtersForm);
          //rotates the text, to place it on the arrow
          var affineTransform = new AffineTransform();
          affineTransform.rotate(0.15);
          var defaultFont = g2d.getFont();
          var font = new Font(g2d.getFont().getFontName(), Font.PLAIN, 12).deriveFont(affineTransform);
          g2d.setFont(font);
          var tcpOptionsAndWinSize = packetDisplayService.getTcpOptionsForPacket(pkt, filtersForm);
          //if tcp options are very long, moves them slightly to the left
          if (tcpOptionsAndWinSize.length() < 30) {
            g2d.drawString(tcpOptionsAndWinSize, midpoint.x - 80, midpoint.y + 10);
          } else {
            g2d.drawString(tcpOptionsAndWinSize, midpoint.x - 150, midpoint.y);
          }
          g2d.drawString(lineLabel, midpoint.x-80, midpoint.y-20);
          //resets the font back to default, so its not rotated anymore
          g2d.setFont(defaultFont);
        } else {
          //similarly to above for incoming packet, right to left arrow
          leftPoint.x = leftXPos;
          rightPoint.y = currentVerticalPosition;
          currentVerticalPosition = currentVerticalPosition + 70;
          leftPoint.y = currentVerticalPosition;
          rightPoint.x = rightXPos;
          g2d.drawString(packetDisplayService.getStatusForPacket(pkt, selectedConnection).getDisplayText(), rightXLabelPos, currentVerticalPosition-65);
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
          currentHeight += 200;
          //once arrows start being drawn outside of the visible area, increases height of the scroll panel
        }
        if(selectedPkt != null
          && selectedPkt.equals(pkt)) {
          selectedPktYPos = currentVerticalPosition - 210;
          if (setViewportToSelectedPkt.get()) {
            //once a packet has been clicked in the log, this moves the viewport to the clicked packet
            scrollPane.getViewport().setViewPosition(new Point(0, selectedPktYPos));
            setViewportToSelectedPkt.set(false);
          }
        }
        g2d.setColor(Color.BLACK);
      });
    //sets the default status, so the packet connection traversal can happen again on repaint.
    selectedConnection.setStatusAsOfPacketTraversal(ConnectionStatus.UNKNOWN);
  }

  /* Draws an arrow between two points.
   */
  public void drawArrow(Graphics2D g2d, Point startPoint, Point endPoint) {
    int arrowSize = 16;
    double angle = Math.atan2(
            endPoint.getY() - startPoint.getY(),
            endPoint.getX() - startPoint.getX());

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

  private Point midpoint(Point p1, Point p2) {
    return new Point((int) ((p1.x + p2.x)/2.0), (int) ((p1.y + p2.y)/2.0));
  }

  public void setFilters(FiltersForm filtersForm) {
    this.filtersForm = filtersForm;
  }

  /* This is called once a packet has been clicked in the packet log.
   */
  public void setSelectedPacket(EasyTCPacket pkt, boolean setViewport) {
    if (this.selectedPkt != null) {
      this.selectedPkt.setSelectedPacket(false);
    }
    this.selectedPkt = pkt;
    if (pkt != null) {
      this.selectedPkt.setSelectedPacket(true);
    }
    repaint();
    revalidate();

    if (pkt != null && setViewport) {
      var packets = pkt.getTcpConnection().getPacketContainer().getPackets();
      var packetLocY = INITIAL_VERTICAL_POSITION - 70;
      //gets the y position of the selected packet
      for (EasyTCPacket currentPacket : packets) {
        if (currentPacket.equals(selectedPkt)) {
          setViewportToSelectedPkt.set(true);
          this.selectedPktYPos = packetLocY;
          break;
        }
        packetLocY += 140;
      }
    }
  }

  /* Saves the arrows diagram as a png
   */
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

  public TCPConnection getSelectedConnection() {
    return selectedConnection;
  }

  @Override
  public Dimension getPreferredSize() {
    return new Dimension(arrowDiagramWidth, currentHeight);
  }
}
