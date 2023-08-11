package view;

import controller.FiltersForm;

import javax.swing.*;
import java.awt.*;

public class OptionsPanel extends JPanel {
  private final FiltersForm filtersForm;

  public OptionsPanel(FiltersForm filtersForm) {
    super();
    this.filtersForm = filtersForm;
    var layout = new GridLayout();
    layout.setColumns(2);
    layout.setRows(3);
    setLayout(layout);

    var resolveHostnames = new JCheckBox();
    resolveHostnames.setText("Resolve hostnames");
    add(resolveHostnames);

    var ipv4Checkbox = new JCheckBox();
    ipv4Checkbox.setText("IPv4");
    add(ipv4Checkbox);

    var ipv6Checkbox = new JCheckBox();
    ipv6Checkbox.setText("IPv6");
    add(ipv6Checkbox);
  }
}
