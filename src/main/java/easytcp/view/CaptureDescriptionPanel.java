package easytcp.view;

import easytcp.model.application.CaptureData;

import javax.swing.*;
import java.awt.*;

public class CaptureDescriptionPanel {
  private final JPanel descriptionPanel;
  private final JLabel connectionCountLabel;
  private final JLabel packetCountLabel;

  public CaptureDescriptionPanel(CaptureData captureData) {
    this.descriptionPanel = new JPanel();
    var layout = new GridLayout();
    layout.setRows(2);
    layout.setColumns(1);
    descriptionPanel.setLayout(layout);
    connectionCountLabel = new JLabel();
    connectionCountLabel.setText("%s TCP connections".formatted(captureData.getTcpConnectionsEstablished()));
    descriptionPanel.add(connectionCountLabel);
    packetCountLabel = new JLabel();
    packetCountLabel.setText("%s packets captured".formatted(captureData.getPackets().size()));
    descriptionPanel.add(packetCountLabel);
  }

  public void updateCaptureStats(CaptureData captureData) {
    connectionCountLabel.setText("%s TCP connections".formatted(captureData.getTcpConnectionsEstablished()));
    packetCountLabel.setText("%s packets captured".formatted(captureData.getPackets().size()));
    descriptionPanel.revalidate();
    descriptionPanel.repaint();
  }

  public JPanel getDescriptionPanel() {
    return descriptionPanel;
  }
}
