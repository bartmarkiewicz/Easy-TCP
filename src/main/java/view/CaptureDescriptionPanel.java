package view;

import model.CaptureStats;

import javax.swing.*;
import java.awt.*;

public class CaptureDescriptionPanel extends JPanel {
  private JLabel connectionCountLabel;
  private JLabel packetCountLabel;

  public CaptureDescriptionPanel(CaptureStats captureStats) {
    super();
    var layout = new GridLayout();
    layout.setRows(2);
    layout.setColumns(1);
    setLayout(layout);
    connectionCountLabel = new JLabel();
    connectionCountLabel.setText("%s TCP connections".formatted(captureStats.getTcpConnectionsEstablished()));
    add(connectionCountLabel);
    packetCountLabel = new JLabel();
    packetCountLabel.setText("%s packets captured".formatted(captureStats.getPacketsCaptured()));
    add(packetCountLabel);
  }

  public void updateCaptureStats(CaptureStats captureStats) {
    connectionCountLabel.setText("%s TCP connections".formatted(captureStats.getTcpConnectionsEstablished()));
    packetCountLabel.setText("%s packets captured".formatted(captureStats.getPacketsCaptured()));
    revalidate();
    repaint();
  }
}
