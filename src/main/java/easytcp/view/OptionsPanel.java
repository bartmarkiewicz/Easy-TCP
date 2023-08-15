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
import java.util.concurrent.atomic.AtomicBoolean;

public class OptionsPanel {
  private static final Logger LOGGER = LoggerFactory.getLogger(OptionsPanel.class);

  private final JPanel panel;
  private final FiltersForm filtersForm;
  private final PacketLog packetLog;
  private final HashMap<String, PcapNetworkInterface> deviceNetworkInterfaceHashMap = new HashMap<>();
  private CaptureDescriptionPanel captureDescriptionPanel;

  public OptionsPanel(FiltersForm filtersForm, PacketLog packetLog) {
  // while capturing use BPF filter, dont allow changing filters during capture
  // when stopped capture or read a file, use frontend filters

    this.panel = new JPanel();
    this.packetLog = packetLog;
    this.captureDescriptionPanel= new CaptureDescriptionPanel(this.packetLog.getCaptureData());
    this.filtersForm = filtersForm;
    var layout = new GridLayout();
    layout.setHgap(110);
    layout.setVgap(50);
    layout.setColumns(1);
    layout.setRows(3);
    panel.setLayout(layout);
    var topRow = new JPanel();
    var topRowLayout = new GridLayout();
    topRowLayout.setRows(1);
    topRowLayout.setColumns(3);
    topRowLayout.setVgap(50);
    topRowLayout.setHgap(50);
    topRow.setLayout(topRowLayout);
    addFilters(topRow);
    panel.add(topRow);
    panel.add(createMiddleRow());
    var bottomRow = new JPanel();
    var bottomRowLayout = new GridLayout();
    bottomRowLayout.setColumns(3);
    bottomRowLayout.setRows(1);
    bottomRowLayout.setVgap(50);
    bottomRowLayout.setHgap(50);
    bottomRow.setLayout(bottomRowLayout);
    addButtons(bottomRow);
    panel.add(bottomRow);
  }

  private JPanel createMiddleRow() {
    var middleRowPanel = new JPanel();
    middleRowPanel.setBackground(Color.YELLOW);
    var middleRowLayout = new GridLayout();
    middleRowLayout.setColumns(3);
    middleRowLayout.setRows(1);
    middleRowPanel.setLayout(middleRowLayout);
    var connectionLabel = new JLabel();
    connectionLabel.setText("""
    Connection information
    """);
    middleRowPanel.add(connectionLabel);
    middleRowPanel.add(new JPanel());

    var inputFieldsContainer = new JPanel();
    var inputFieldsLayout = new GridLayout();
    inputFieldsLayout.setRows(2);
    inputFieldsLayout.setColumns(1);
    inputFieldsContainer.setLayout(inputFieldsLayout);
    var portContainer = new JPanel();
    var rowLayout = new BorderLayout();
    rowLayout.setHgap(25);
    rowLayout.setVgap(25);
    var rowLayout2 = new BorderLayout();
    rowLayout2.setHgap(25);
    rowLayout2.setVgap(25);
    portContainer.setLayout(rowLayout);
    var hostContainer = new JPanel();
    hostContainer.setLayout(rowLayout2);
    var portInput = new JTextField();
    var portLabel = new JLabel("Port");
    portInput.add(portLabel);
    var hostInput = new JTextField();
    var hostLabel = new JLabel("Host");
    hostLabel.setHorizontalAlignment(SwingConstants.RIGHT);
    portLabel.setHorizontalAlignment(SwingConstants.RIGHT);
    portContainer.add(portLabel, BorderLayout.LINE_START);
    portContainer.add(portInput, BorderLayout.CENTER);
    hostContainer.add(hostLabel, BorderLayout.LINE_START);
    hostContainer.add(hostInput, BorderLayout.CENTER);

    portInput.getDocument().addDocumentListener((DocumentUpdateListener) e -> {
      this.filtersForm.setPortRangeSelected(portInput.getText());
    });

    hostInput.getDocument().addDocumentListener((DocumentUpdateListener) e -> {
      this.filtersForm.setHostSelected(hostInput.getText());
    });

    inputFieldsContainer.add(portContainer);
    inputFieldsContainer.add(hostContainer);

    middleRowPanel.add(inputFieldsContainer);

    return middleRowPanel;
  }

  private void addButtons(JPanel row) {
    var defaultsBt = new JButton("Restore defaults");
    captureDescriptionPanel.getDescriptionPanel().setBackground(Color.RED);
    row.add(captureDescriptionPanel.getDescriptionPanel());
    row.setBackground(Color.CYAN);
    defaultsBt.setSize(200, 200);
    row.add(defaultsBt);
    defaultsBt.addActionListener((event) ->
      this.filtersForm.restoreDefaults()
    );
    var filterBt = new JButton("Filter");
    filterBt.setSize(200, 200);

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
    var isCapturing = new AtomicBoolean(false);

    button.addActionListener((event) -> {
      var networkInterface = deviceNetworkInterfaceHashMap.get((String) interfaceSelect.getSelectedItem());
      if (networkInterface != null) {
        SwingUtilities.invokeLater(() -> {
          if (button.getText().equals("Start capture")) {
            isCapturing.set(true);
            button.setText("Stop capture");
          } else {
            button.setText("Start capture");
            isCapturing.set(false);
          }
        });
        var thread = Executors.newSingleThreadExecutor();
        thread.execute(
          () -> {
            try {
              packetLog.startPacketCapture(
                networkInterface, isCapturing.get(), captureDescriptionPanel);
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
