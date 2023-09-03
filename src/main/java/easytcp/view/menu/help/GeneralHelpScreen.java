package easytcp.view.menu.help;

import easytcp.view.ScrollableJPanel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;

/* Represents the general help screen window
 */
public class GeneralHelpScreen {
  private static final Logger LOGGER = LoggerFactory.getLogger(GeneralHelpScreen.class);
  private final JFrame frame;

  public GeneralHelpScreen() {
    this.frame = new JFrame("Easy TCP General Help");
    var screenSize = Toolkit.getDefaultToolkit().getScreenSize();
    screenSize.setSize(screenSize.width - 120, screenSize.height - 120);
    frame.setSize(screenSize);
    frame.setPreferredSize(screenSize);
    frame.setLayout(new BorderLayout());
    var heading = new JLabel("Easy TCP user guide");
    heading.setName("header");
    heading.setHorizontalAlignment(SwingConstants.CENTER);
    frame.add(heading, BorderLayout.NORTH);
    var containerScrollPanel = new ScrollableJPanel(true);
    containerScrollPanel.currentHeight = 1600;
    containerScrollPanel.COMPONENT_WIDTH = frame.getWidth()+200;

    containerScrollPanel.setLayout(new GridLayout(1,1));
    JPanel containerPanel = new JPanel();
    var panelLayout = new GridLayout();
    panelLayout.setRows(3);

    panelLayout.setColumns(3);
    panelLayout.setVgap(30);
    panelLayout.setHgap(30);

    containerPanel.setLayout(panelLayout);
    containerScrollPanel.add(containerPanel);

    var containerScrollPane = new JScrollPane(
      containerScrollPanel, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
    addContents(containerPanel);

    frame.add(containerScrollPane, BorderLayout.CENTER);
    var closeBt = new JButton("Close");
    closeBt.addActionListener(e ->
      frame.dispose()
    );
    frame.add(closeBt, BorderLayout.PAGE_END);

    frame.setVisible(true);
  }

  private void addContents(JPanel containerPanel) {
    try {
      var arrowDiagramImg = ImageIO.read(new File("src/main/resources/arrowsDiagram.png"));
      var arrowDiagramDescription = new JTextPane();
      arrowDiagramDescription.setEditable(false);
      var arrowDiagramDescriptionScrollPane = new JScrollPane(arrowDiagramDescription);
      arrowDiagramDescription.setText("""
      Arrow Diagram
      
      The arrow diagram consists of the client on the left, which represents the network interface the packet \
      capture was started upon. The section on the right represents the server or the host the client initiates a contact with.
      
      The user must first select a connection and filter or click a packet in the packet capture log after conducting a packet capture session or \
      reading a pcap file to see the Arrows Diagram.
      
      On the sides of the arrows diagram we can see relative timestamp (from the first packet captured on the connection).
      The segment number captured, and the status change on that connection following the receiving of that packet - if any. \
      Arrows on the diagram indicate the direction of sending, an arrow going from left to right indicates a packet sent by the left host or client \
      An arrow going from right to left, indicates a packet going from the server to the client.
      
      On the picture we can see an initial starting status of SYN SENT, initiated by the server, to which the client responds and
      the status is changed to SYN received.
      
      The arrows diagram can be customised with the filters described below. At its most detailed the arrow labels show flags, \
      ack and sequence numbers, TCP options on  the packet, the data payload lengths and the window size on the arrows themselves.
      """);
      arrowDiagramDescription.setCaretPosition(0);
      JLabel picLabel = new JLabel();
      containerPanel.add(arrowDiagramDescriptionScrollPane);
      containerPanel.add(picLabel);
      var scaledImg = arrowDiagramImg.getScaledInstance((frame.getWidth()/2)-40, (frame.getHeight()/2)-40, Image.SCALE_SMOOTH);
      picLabel.setIcon(new ImageIcon(scaledImg));
      var optionsDescription = new JTextPane();
      optionsDescription.setEditable(false);
      var optionsDescriptionScrollPane = new JScrollPane(optionsDescription);
      optionsDescription.setText("""
      Options Panel
      
      The options on the right of Easy TCP allows customisation of what the user wants to see.
      
      The checkboxes once ticked -
      1. Resolve hostnames - enables host name resolution when packet capturing or reading a file, \
      this allows the user to see the names of hosts rather than their numerical IP addresses.
      2. Header flags, once ticked shows TCP flags on the arrows diagram and on the connection description.
      3. IPv4 - shows or captures packets which use IP protocol version 4.
      4. IPv6 - shows or captures packets which use IP protocol version 6, albeit these packets are pretty uncommon for TCP.
      5. Show window size - displays the current window size on a packet on the arrows diagram.
      6. Payload length - displays the payload length on each packet on the arrows diagram.
      7. Ack and sequence numbers - displays the acknowledgement and sequence numbers on the arrows diagram.
      8. TCP options - shows or hides the TCP options displayed on the arrows diagram
      9. Show detected TCP features - shows the suspected TCP features and strategies employed on the connection on the connection description,
      10. Show general information - shows the general information acquired about a connection on the connection description.
      
      On the right of the checkboxes there is the interface selector field, where the user can select the desired network interface \
      to start capturing packets on. Under the network interface selector, the start capture button begins a live capture of packets on \
      the selected interface, matching the filters selected by the user.
      
      Under the checkboxes on the left in the middle there is a general count of the connections detected and their statuses.
      
      In the middle we have the connection selector, once a file has been read or a packet capture is ongoing or finished, \
      the user can select one of the connections between two hosts to display information about it. Additionally it can be used as a filter for the packet log \
      and the packet capture, ensuring only packets on that connection are captured. Under the connection selector we have the \
      selected connection description this gets populated with the information about the connection matching the filters once the filter button is clicked after selecting \
      a connection.
      
      On the right in the middle we have the feature detection sensitivity, due to the nature of analysing packets without knowledge \
      of the underlying network and connection configurations, just based on the patterns in a pcap file, it is often uncertain if a \
      particular strategy or feature is enabled. Strict means only features with a high degree of certainty appear in the selected connection \
      description, lenient means if there is some evidence to a particular strategy, it will display, lastly balanced tries to strike a balance between the two.
      
      Underneath the sensitivity, there is the port input field which allows the user to supply a port to filter results or capture results only on a particular port \
      or port range written in the format STARTPORT-ENDPORT. There is also the host ip or hostname input, which allows the user to filter results or capture based on \
      a particular hostname or host ip. It must be noted port and host are filters which apply on either a destination port/ip or a source port/ip.
      
      On the last row of the options panel we have the general capture description which shows how many packets match the filters and how many connections have been detected.
      
      The buttons on the last row allow the user to restore the default filters - which show the most vital information, and allow the user
      to re-filter the output after a capture or file read.
      """);
      optionsDescription.setCaretPosition(0);
      var optionsPic = ImageIO.read(new File("src/main/resources/optionsPic.png"));
      var scaledOptImg = optionsPic.getScaledInstance((frame.getWidth()/2)-40, (int) (frame.getHeight()/1.5), Image.SCALE_SMOOTH);

      var optionsPicLabel = new JLabel(new ImageIcon(scaledOptImg));
      containerPanel.add(optionsPicLabel);
      containerPanel.add(optionsDescriptionScrollPane);



      var packetLogImg = ImageIO.read(new File("src/main/resources/packetLog.png"));
      var packetLogDescription = new JTextPane();
      packetLogDescription.setEditable(false);
      var packetLogDescriptionScrollPane = new JScrollPane(packetLogDescription);
      packetLogDescription.setText("""
      Packet Log
      
      The packet log shows a text based output of the captured packets in a format akin to a tcpdump. \
      The packets have the timestamp of having been received or sent from the network interface which is doing the capturing \
      this is followed by their protocol version, followed by the IP address or hostname depending on the filters, first the sender address \
      followed by the receiver. This is then followed by the flags on the TCP connection, the flags are abbreviated to just the first letter, and \
      a dot for the ACK. Then the sequence number and the ack number is displayed. Followed by the window size and  \
      the options field in the form of a list of bit values, lastly the length of the payload is displayed. 
      
      The user can click on a packet on the packet log to view the packet on the arrows diagram. This will immediately show the diagram \
      for that connection and highlight the captured packet in blue. 
      """);
      packetLogDescription.setCaretPosition(0);
      var packetLogPicLabel = new JLabel();
      containerPanel.add(packetLogDescriptionScrollPane);
      var scaledPktLogImg = packetLogImg.getScaledInstance((int)(frame.getWidth()/1.5), packetLogImg.getHeight(), Image.SCALE_SMOOTH);
      containerPanel.add(packetLogPicLabel);

      packetLogPicLabel.setIcon(new ImageIcon(scaledPktLogImg));
    } catch (IOException e) {
      LOGGER.debug(e.getMessage());
    }
  }
}
