package view;

import controller.FiltersForm;
import controller.PacketLogger;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;

public class OptionsPanel extends JPanel {
  private static final Logger LOGGER = LoggerFactory.getLogger(OptionsPanel.class);

  private final FiltersForm filtersForm;
  private final PacketLogger packetLogger;
  private final HashMap<String, PcapNetworkInterface> deviceNetworkInterfaceHashMap = new HashMap<>();

  public OptionsPanel(FiltersForm filtersForm, PacketLogger packetLogger) {
    super();
    this.packetLogger = packetLogger;
    this.filtersForm = filtersForm;
    var layout = new GridLayout();
    layout.setColumns(1);
    layout.setRows(3);
    setLayout(layout);
    var topRow = new JPanel();
    var topRowLayout = new GridLayout();
    topRowLayout.setRows(1);
    topRowLayout.setColumns(2);
    addFilters(topRow);
    add(topRow);
    add(new JPanel());
    var bottomRow = new JPanel();
    var bottomRowLayout = new GridLayout();
    bottomRowLayout.setColumns(3);
    bottomRowLayout.setRows(1);
    bottomRow.setLayout(bottomRowLayout);
    addButtons(bottomRow);
    add(bottomRow);
  }

  private void addButtons(JPanel row) {
    var defaultsBt = new JButton("Restore defaults");
    var descriptionPanel = new CaptureDescriptionPanel(this.packetLogger.getCaptureStats());
    descriptionPanel.setBackground(Color.RED);
    row.add(descriptionPanel);
    row.setBackground(Color.CYAN);
    row.add(defaultsBt);
    defaultsBt.addActionListener((event) ->
      this.filtersForm.restoreDefaults()
    );
    var filterBt = new JButton("Filter");
    filterBt.addActionListener((event) -> {
        descriptionPanel.updateCaptureStats(this.packetLogger.getCaptureStats());
        this.packetLogger.refilterPackets();
      }
    );
    row.add(filterBt);
  }

  private void addFilters(JPanel topRow) {
    var checkboxLayout = new GridLayout();
    checkboxLayout.setColumns(1);
    checkboxLayout.setRows(3);
    var checkboxContainer = new JPanel();
    checkboxContainer.setLayout(checkboxLayout);

    var resolveHostnames = new JCheckBox();
    resolveHostnames.setText("Resolve hostnames");
    resolveHostnames.setSelected(filtersForm.isResolveHostnames());
    resolveHostnames.addChangeListener((changeEvent) -> {
      this.filtersForm.setResolveHostnames(resolveHostnames.isSelected());
    });
    checkboxContainer.add(resolveHostnames);

    var ipv4Checkbox = new JCheckBox();
    ipv4Checkbox.setText("IPv4");
    ipv4Checkbox.addChangeListener((changeEvent) -> {
      this.filtersForm.setShowIpv4(ipv4Checkbox.isSelected());
    });
    ipv4Checkbox.setSelected(filtersForm.isShowIpv4());
    checkboxContainer.add(ipv4Checkbox);

    var ipv6Checkbox = new JCheckBox();
    ipv6Checkbox.setText("IPv6");
    ipv6Checkbox.setSelected(filtersForm.isShowIpv6());
    ipv6Checkbox.addChangeListener((changeEvent) -> {
      this.filtersForm.setShowIpv6(ipv6Checkbox.isSelected());
    });
    checkboxContainer.add(ipv6Checkbox);

    try {
      Pcaps.findAllDevs()
        .forEach(pcapNetworkInterface ->
          //description is more human readable than name
          deviceNetworkInterfaceHashMap.put(pcapNetworkInterface.getDescription(), pcapNetworkInterface));
    } catch (PcapNativeException e) {
      LOGGER.debug("Could not find all network interfaces");
    }
    var interfaceSelect = deviceNetworkInterfaceHashMap.keySet().toArray();

    var interfaceList = new JComboBox<>(interfaceSelect);
    interfaceList.addActionListener((event) -> {
      interfaceList.getSelectedItem();
    });

    topRow.add(checkboxContainer);
    topRow.add(interfaceList);
  }
}
