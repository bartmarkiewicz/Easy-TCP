package easytcp.view.options;

import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.EasyTCPacket;
import easytcp.service.PacketDisplayService;
import easytcp.service.ServiceProvider;

import javax.swing.*;
import java.awt.*;

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
    setConnectionCountLabel(captureData);
    descriptionPanel.add(connectionCountLabel);
    packetCountLabel = new JLabel();
    packetCountLabel.setText("%s packets captured".formatted(captureData.getPackets()
      .getPackets().stream().filter(pkt -> packetDisplayService.isVisible(pkt, FiltersForm.getFiltersForm())).count()));
    descriptionPanel.add(packetCountLabel);
  }

  public void updateCaptureStats(CaptureData captureData) {
    setConnectionCountLabel(captureData);
    packetCountLabel.setText("%s packets captured".formatted(captureData.getPackets()
      .getPackets().stream().filter(pkt -> packetDisplayService.isVisible(pkt, FiltersForm.getFiltersForm())).count()));
    descriptionPanel.revalidate(); //todo make packets captured update with
    descriptionPanel.repaint();
  }

  public JPanel getDescriptionPanel() {
    return descriptionPanel;
  }

  private void setConnectionCountLabel(CaptureData captureData) {
    SwingUtilities.invokeLater(() -> {
      connectionCountLabel.setText("""
      %s TCP connections
      """.formatted(captureData.getPackets()
        .getPackets()
        .stream()
        .filter(pkt -> packetDisplayService.isVisible(pkt, FiltersForm.getFiltersForm()))
        .map(EasyTCPacket::getTcpConnection)
        .distinct()
        .count()));
    });
  }
}
