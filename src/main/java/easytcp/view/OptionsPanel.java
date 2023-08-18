package easytcp.view;

import easytcp.model.CaptureStatus;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
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
  private final MiddleRow middleRow;
  private final FiltersForm filtersForm;
  private final PacketLog packetLog;
  private final HashMap<String, PcapNetworkInterface> deviceNetworkInterfaceHashMap = new HashMap<>();
  private final CaptureDescriptionPanel captureDescriptionPanel;
  private JCheckBox ipv6Checkbox;
  private JCheckBox ipv4Checkbox;
  private JCheckBox resolveHostnames;

  public OptionsPanel(FiltersForm filtersForm, PacketLog packetLog) {
    this.panel = new JPanel();
    this.packetLog = packetLog;
    this.captureDescriptionPanel= new CaptureDescriptionPanel(this.packetLog.getCaptureData());
    this.filtersForm = filtersForm;
    var layout = new GridBagLayout();
    var overallConstraints = new GridBagConstraints();

    layout.setConstraints(panel, overallConstraints);
    var rowOneConstraints = new GridBagConstraints();
    rowOneConstraints.gridx = 0;
    rowOneConstraints.gridy = 0;
    rowOneConstraints.weighty = 0.01;
    rowOneConstraints.weightx = 1;
    rowOneConstraints.fill = GridBagConstraints.BOTH;
    rowOneConstraints.ipadx = 10;
    rowOneConstraints.ipady = 10;
    panel.setLayout(layout);
    panel.setBackground(Color.YELLOW);
    var topRow = new JPanel();
    var topRowLayout = new GridLayout();
    topRowLayout.setRows(1);
    topRowLayout.setColumns(3);
    topRowLayout.setVgap(10);
    topRowLayout.setHgap(10);
    topRow.setLayout(topRowLayout);
    addFilters(topRow);
    panel.add(topRow, rowOneConstraints);

    this.middleRow = new MiddleRow(filtersForm);
    middleRow.setConnectionStatusLabel(CaptureData.getCaptureData());

    var middleRowConstraints = new GridBagConstraints();
    middleRowConstraints.gridx = 0;
    middleRowConstraints.gridy = 1;
    middleRowConstraints.fill = GridBagConstraints.BOTH;
    middleRowConstraints.weighty = 0.6;
    middleRowConstraints.weightx = 1;
    middleRowConstraints.ipadx = 10;
    middleRowConstraints.ipady = 10;
    panel.add(middleRow.getPanel(), middleRowConstraints);
    var bottomRow = new JPanel();
    var bottomRowLayout = new GridLayout();
    bottomRowLayout.setColumns(3);
    bottomRowLayout.setRows(1);
    bottomRowLayout.setHgap(10);
    bottomRow.setLayout(bottomRowLayout);
    addButtons(bottomRow);

    var bottomRowConstraints = new GridBagConstraints();
    bottomRowConstraints.gridx = 0;
    bottomRowConstraints.gridy = 2;
    bottomRowConstraints.fill = GridBagConstraints.BOTH;
    bottomRowConstraints.weighty = 0.1;
    bottomRowConstraints.weightx = 1;
    bottomRowConstraints.ipadx = 10;
    bottomRowConstraints.ipady = 10;

    panel.add(bottomRow, bottomRowConstraints);
  }

  private void addButtons(JPanel row) {
    var defaultsBt = new JButton("Restore defaults");
    captureDescriptionPanel.getDescriptionPanel().setBackground(Color.RED);
    row.add(captureDescriptionPanel.getDescriptionPanel());
    defaultsBt.setSize(200, 200);
    row.add(defaultsBt);
    defaultsBt.addActionListener((event) -> {
      this.filtersForm.restoreDefaults();
      this.middleRow.resetConnectionInformation();
      restoreFilters();
      }
    );
    var filterBt = new JButton("Filter");
    filterBt.setSize(200, 200);

    filterBt.addActionListener((event) -> {
      if (!ApplicationStatus.getStatus().isLiveCapturing().get() && !ApplicationStatus.getStatus().isLoading().get()) {
        this.packetLog.refilterPackets();
        captureDescriptionPanel.updateCaptureStats(this.packetLog.getCaptureData());
        middleRow.setConnectionStatusLabel(this.packetLog.getCaptureData());
      } else {
        JOptionPane.showMessageDialog(
          captureDescriptionPanel.getDescriptionPanel(),
          "You cannot change your filter while live capturing packets or loading a file " +
            "stop your capture or wait for the file to finish loading before trying again");
      }
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

    resolveHostnames = new JCheckBox();
    resolveHostnames.setText("Resolve hostnames");
    resolveHostnames.setSelected(filtersForm.isResolveHostnames());
    resolveHostnames.addChangeListener((changeEvent) -> {
      this.filtersForm.setResolveHostnames(resolveHostnames.isSelected());
    });
    checkboxContainer.add(resolveHostnames);

    ipv4Checkbox = new JCheckBox();
    ipv4Checkbox.setText("IPv4");
    ipv4Checkbox.addChangeListener((changeEvent) -> {
      this.filtersForm.setShowIpv4(ipv4Checkbox.isSelected());
    });
    ipv4Checkbox.setSelected(filtersForm.isShowIpv4());
    checkboxContainer.add(ipv4Checkbox);

    ipv6Checkbox = new JCheckBox();
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
    this.filtersForm.setSelectedInterface(
      deviceNetworkInterfaceHashMap.get(interfaceList.getSelectedItem()));
    interfaceList.addActionListener((event) -> {
      interfaceList.getSelectedItem();
      this.filtersForm.setSelectedInterface(
        deviceNetworkInterfaceHashMap.get(interfaceList.getSelectedItem()));
    });

    topRow.add(checkboxContainer);
    topRow.add(interfaceList);
    topRow.add(getStartLiveCaptureButton(interfaceList));
  }

  public void restoreFilters() {
    ipv4Checkbox.setSelected(filtersForm.isShowIpv4());
    ipv6Checkbox.setSelected(filtersForm.isShowIpv6());
    resolveHostnames.setSelected(filtersForm.isResolveHostnames());
  }

  private JButton getStartLiveCaptureButton(JComboBox interfaceSelect) {
    var button = new JButton("Start capture");
    button.addActionListener((event) -> {
      var networkInterface = deviceNetworkInterfaceHashMap.get((String) interfaceSelect.getSelectedItem());
      if (networkInterface != null) {
        Executors.newSingleThreadExecutor().execute(
          () -> {
            try {
              packetLog.startPacketCapture(
                networkInterface, middleRow, captureDescriptionPanel);
              SwingUtilities.invokeLater(() -> {
                if (ApplicationStatus.getStatus().isLiveCapturing().get()
                  && ApplicationStatus.getStatus().getMethodOfCapture() == CaptureStatus.LIVE_CAPTURE) {
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

  public MiddleRow getMiddleRow() {
    return middleRow;
  }
}
