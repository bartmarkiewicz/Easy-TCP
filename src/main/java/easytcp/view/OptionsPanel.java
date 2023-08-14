package easytcp.view;

import easytcp.model.FiltersForm;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.concurrent.Executors;

public class OptionsPanel {
  private static final Logger LOGGER = LoggerFactory.getLogger(OptionsPanel.class);

  private final JPanel panel;
  private final FiltersForm filtersForm;
  private final PacketLog packetLog;
  private final HashMap<String, PcapNetworkInterface> deviceNetworkInterfaceHashMap = new HashMap<>();
  private CaptureDescriptionPanel captureDescriptionPanel;

  public OptionsPanel(FiltersForm filtersForm, PacketLog packetLog) {
    this.panel = new JPanel();
    this.packetLog = packetLog;
    this.captureDescriptionPanel= new CaptureDescriptionPanel(this.packetLog.getCaptureData());
    this.filtersForm = filtersForm;
    var layout = new GridLayout();
    layout.setColumns(1);
    layout.setRows(3);
    panel.setLayout(layout);
    var topRow = new JPanel();
    var topRowLayout = new GridLayout();
    topRowLayout.setRows(1);
    topRowLayout.setColumns(3);
    topRow.setLayout(topRowLayout);
    addFilters(topRow);
    panel.add(topRow);
    panel.add(new JPanel());
    var bottomRow = new JPanel();
    var bottomRowLayout = new GridLayout();
    bottomRowLayout.setColumns(3);
    bottomRowLayout.setRows(1);
    bottomRow.setLayout(bottomRowLayout);
    addButtons(bottomRow);
    panel.add(bottomRow);
  }

  private void addButtons(JPanel row) {
    var defaultsBt = new JButton("Restore defaults");
    captureDescriptionPanel.getDescriptionPanel().setBackground(Color.RED);
    row.add(captureDescriptionPanel.getDescriptionPanel());
    row.setBackground(Color.CYAN);
    row.add(defaultsBt);
    defaultsBt.addActionListener((event) ->
      this.filtersForm.restoreDefaults()
    );
    var filterBt = new JButton("Filter");
    filterBt.addActionListener((event) -> {
        this.packetLog.refilterPackets();
        captureDescriptionPanel.updateCaptureStats(this.packetLog.getCaptureData());
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
    topRow.add(getStartLiveCaptureButton(interfaceList));
  }

  private JButton getStartLiveCaptureButton(JComboBox interfaceSelect) {
    var button = new JButton("Start capture");
    button.addActionListener((event) -> {
      var networkInterface = deviceNetworkInterfaceHashMap.get((String) interfaceSelect.getSelectedItem());
      var startingCapture = button.getText().equals("Start capture");
      if (networkInterface != null) {
        var thread = Executors.newSingleThreadExecutor();
        thread.execute(
          () -> {
            try {
              packetLog.startPacketCapture(networkInterface, !startingCapture, captureDescriptionPanel);
              SwingUtilities.invokeLater(() -> {
                if (startingCapture) {
                  button.setText("Stop capture");
                } else {
                  button.setText("Start capture");
                }
              });
            } catch (Exception e) {
              e.printStackTrace();
              System.out.println("Could not start packet capture");
            }
          });
      } else {
        System.out.println("Error reading interface.");
      }
    });
    return button;
  }

  public JPanel getPanel() {
    return panel;
  }

  public CaptureDescriptionPanel getCaptureDescriptionPanel() {
    return this.captureDescriptionPanel;
  }
}
