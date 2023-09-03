package easytcp.view.options;

import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.EasyTCPacket;
import easytcp.service.PacketDisplayService;
import easytcp.service.ServiceProvider;

import javax.swing.*;
import java.awt.*;

/* This is the small capture description panel in the corner of the options panel
 */
public class CaptureDescriptionPanel {
  private final JPanel descriptionPanel;
  private final JLabel connectionCountLabel;
  private final JLabel packetCountLabel;
  private final PacketDisplayService packetDisplayService;

  public CaptureDescriptionPanel(CaptureData captureData) {
    this.descriptionPanel = new JPanel();
    this.packetDisplayService = ServiceProvider.getInstance().getPacketDisplayService();
    var layout = new GridLayout();
    layout.setRows(2);
    layout.setColumns(1);
    descriptionPanel.setLayout(layout);
    connectionCountLabel = new JLabel();
    connectionCountLabel.setName("connection count");
    setConnectionCountLabel(captureData);
    descriptionPanel.add(connectionCountLabel);
    packetCountLabel = new JLabel();
    packetCountLabel.setName("packets count");
    packetCountLabel.setText("%s packets captured".formatted(captureData.getPackets()
      .getPackets().stream().filter(pkt -> packetDisplayService.isVisible(pkt, FiltersForm.getInstance())).count()));
    descriptionPanel.add(packetCountLabel);
  }

  public void updateCaptureStats(CaptureData captureData) {
    setConnectionCountLabel(captureData);
    packetCountLabel.setText("%s packets captured".formatted(captureData.getPackets()
      .getPackets().stream().filter(pkt -> packetDisplayService.isVisible(pkt, FiltersForm.getInstance())).count()));
    descriptionPanel.revalidate();
    descriptionPanel.repaint();
  }

  public JPanel getDescriptionPanel() {
    return descriptionPanel;
  }

  private void setConnectionCountLabel(CaptureData captureData) {
    SwingUtilities.invokeLater(() -> connectionCountLabel.setText("""
    %s TCP connections
    """.formatted(captureData.getPackets()
      .getPackets()
      .stream()
      .filter(pkt -> packetDisplayService.isVisible(pkt, FiltersForm.getInstance()))
      .map(EasyTCPacket::getTcpConnection)
      .distinct()
      .count())));
  }
}
