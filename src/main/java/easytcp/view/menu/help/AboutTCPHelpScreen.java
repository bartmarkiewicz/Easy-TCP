package easytcp.view.menu.help;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

public class AboutTCPHelpScreen {
  private static final Logger LOGGER = LoggerFactory.getLogger(AboutTCPHelpScreen.class);
  private final JFrame frame;
  public AboutTCPHelpScreen() {
    this.frame = new JFrame("EasyTCP About TCP");
    var screenSize = Toolkit.getDefaultToolkit().getScreenSize();
    screenSize.setSize(screenSize.width - 120, screenSize.height - 120);
    frame.setSize(screenSize);
    var containerPanel = new JPanel();
    frame.setPreferredSize(screenSize);
    initComponents(containerPanel);
    frame.add(containerPanel);
    frame.setVisible(true);
  }

  private void initComponents(JPanel containerPanel) {
    var layout = new BorderLayout();
    containerPanel.setLayout(layout);
    var leftPanel = new JPanel();
    var topPanel = new JPanel();
    var rightPanel = new JPanel();
    addTcpHeaderToPanel(rightPanel, containerPanel);
    addTcpDescriptionToPanel(leftPanel);
    addHeading(topPanel);
    containerPanel.add(topPanel, BorderLayout.NORTH);
    containerPanel.add(leftPanel, BorderLayout.LINE_START);
    containerPanel.add(rightPanel, BorderLayout.CENTER);
    var closeBt = new JButton("Close");
    closeBt.addActionListener(e -> frame.dispose());
    containerPanel.add(closeBt, BorderLayout.PAGE_END);
  }

  private void addHeading(JPanel topPanel) {
    var headingLabel = new JLabel("Transmission Control Protocol - TCP");
    headingLabel.setName("header");
    headingLabel.setPreferredSize(new Dimension(250, 50));
    topPanel.add(headingLabel);
  }

  private void addTcpDescriptionToPanel(JPanel leftPanel) {
    var tcpDescription = new JTextPane();
    tcpDescription.setText("""
      TCP protocol
      TCP or Transmission Control Protocol is a communications standard that enables applications and computingn \
      devices to communicate over a network. It is designed to send packets between two devices across a network and \
      ensure the successful delivery of data.
      
      Each packet consists of a header and its data, on the right you can see the TCP header. A packet is a segment of data
      that goes through an internet connection, which could be wireless or ethernet.
      
      It is the most commonly used protocol used on the internet, it complements the lower level IP protocol. Due to its popularity  \
      the entire protocol suite is often referred as TCP/IP.
      
      It is connection based, before data can be sent a connection must be established, this is accomplished \
      through the TCP three-way handshake. Reliability is ensured through in-built retransmission and error detection.
      
      The TCP connection begins with a TCP three-way handshake, both sides send a SYN packet to synchronise and \
      acknowledge (ACK) each other, it begins with sending a SYN packet, then a SYN-ACK is received, followed by a sent ACK \
      Following this final ACK a connection is established and the two hosts can send eachother data. \
      The connection orderly ends with a FIN packet sent from a host, which then receives a reply in the form of a FIN and ACK, \
      this is followed with an ACK from the initial host which started the connection termination. After this final ACK the connection is closed. \
      The TCP connection can also be immediately terminated with a RST flag.
      """);
    tcpDescription.setEditable(false);
    tcpDescription.setPreferredSize(new Dimension(600, 500));
    var scrollPane = new JScrollPane(tcpDescription);
    leftPanel.add(scrollPane);
  }

  private void addTcpHeaderToPanel(JPanel rightPanel, JPanel containerPanel) {
    try {
      rightPanel.setLayout(new BoxLayout(rightPanel, BoxLayout.Y_AXIS));
      rightPanel.add(Box.createHorizontalGlue());
      BufferedImage myPicture = ImageIO.read(new File("src/main/resources/tcpHeader.png"));
      JLabel picLabel = new JLabel(new ImageIcon(myPicture));
      rightPanel.add(picLabel);
      var headerHeading = new JLabel("A TCP packet");
      headerHeading.setHorizontalAlignment(SwingConstants.CENTER);
      var headerDescription = new JTextPane();
      headerDescription.setEditable(false);
      var headerDescriptionScrollPane = new JScrollPane(headerDescription);
      headerDescription.setPreferredSize(new Dimension(containerPanel.getWidth()/2, containerPanel.getHeight()/2));
      headerDescription.setText("""
      The TCP header consists of 20-60 bytes, it is sent alongside every TCP packet. Each TCP packet consists of
      1. Source and Destination ports - 16 bit fields that specify the port the data should be sent to.
      2. Sequence number, 32 bit field which is a counter used to keep track of every byte sent outward by a host.
      3. Acknowledgment number, 32 bit field which indicates the sequence number 
      the source next expects to receive from the destination
      4. Data offset, 32 bits, specifies the size of the TCP header
      5. Reserved, 6 bits, these bits are reserved for potential future use.
      6. TCP flags, 6 bits, these signify 6 flags which indicate a particular connection state, they are: 
          SYN - initiates a TCP connection
          ACK - indicates that the packet is acknowledging a previously received packet
          PSH - Tells the receiver to pass on the data to the application as soon as possible, 
          typically disables algorithms such as Nagle
          RST - Immediately ends a TCP connection
          URG - Notifies the received to process the packet before processing all other packets.
          FIN - Gracefully ends a TCP connection
          Less commonly
          CWR - Congestion window reduced, indicates it has received the ECE flag.
          ECE - Ensures the TCP connection is capable of explicit congestion notification (ECN) or used as an indication of network congestion
      7. Window size, 16 bits, indicates the amount of data that the sender is able to accept
      8. Checksum, 16 bits, used for protecting data integrity
      9. Urgent pointer, 16 bits, used to specify where the urgent data is located, when the URG flag is set
      10. Options, maximum 40 bytes, specifies certain optional options on the TCP header below I will outline the primary ones but there are other options used in TCP -
          MSS - Maximum Segment Size
          Window scaling - Used to increase the window size beyond the 16 fields allowed on the window field
          SACK - Selective Ack, when there is a delivery of packets out of order
          SACK permitted - allows SACK on the connection
          Timestamps - sending time and receiving type, used to calculate rount trip time (RTS)
          NOP -  No operation, a seperator between the different options used.
      11. Padding, ensures the the TCP header ends and data begins on a 32 bit boundary.
      12. The data to be transferred
      """);
      rightPanel.add(headerHeading);
      headerDescription.setCaretPosition(0);
      rightPanel.add(headerDescriptionScrollPane);
    } catch (IOException e) {
      LOGGER.debug(e.getMessage());
    }
  }
}
