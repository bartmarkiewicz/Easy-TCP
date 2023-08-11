package view;

import controller.FiltersForm;
import controller.PacketLogger;

import javax.swing.*;
import java.awt.*;

public class OptionsPanel extends JPanel {
  private final FiltersForm filtersForm;
  private final PacketLogger packetLogger;

  public OptionsPanel(FiltersForm filtersForm, PacketLogger packetLogger) {
    super();
    this.packetLogger = packetLogger;
    this.filtersForm = filtersForm;
    var layout = new GridLayout();
    layout.setColumns(2);
    layout.setRows(3);
    setLayout(layout);
    addFilters();
    addButtons();
  }

  private void addButtons() {
    var defaultsBt = new JButton("Restore defaults");
    add(defaultsBt);
    defaultsBt.addActionListener((event) ->
      this.filtersForm.restoreDefaults()
    );
    var filterBt = new JButton("Filter");
    filterBt.addActionListener((event) ->
      this.packetLogger.refilterPackets()
    );
    add(filterBt);
  }

  private void addFilters() {
    var resolveHostnames = new JCheckBox();
    resolveHostnames.setText("Resolve hostnames");
    resolveHostnames.setSelected(filtersForm.isResolveHostnames());
    resolveHostnames.addChangeListener((changeEvent) -> {
      this.filtersForm.setResolveHostnames(resolveHostnames.isSelected());
    });
    add(resolveHostnames);

    var ipv4Checkbox = new JCheckBox();
    ipv4Checkbox.setText("IPv4");
    ipv4Checkbox.addChangeListener((changeEvent) -> {
      this.filtersForm.setShowIpv4(ipv4Checkbox.isSelected());
    });
    ipv4Checkbox.setSelected(filtersForm.isShowIpv4());
    add(ipv4Checkbox);

    var ipv6Checkbox = new JCheckBox();
    ipv6Checkbox.setText("IPv6");
    ipv6Checkbox.setSelected(filtersForm.isShowIpv6());
    ipv6Checkbox.addChangeListener((changeEvent) -> {
      this.filtersForm.setShowIpv6(ipv6Checkbox.isSelected());
    });
    add(ipv6Checkbox);
  }
}
