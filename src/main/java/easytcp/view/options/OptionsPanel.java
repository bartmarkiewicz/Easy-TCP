package easytcp.view.options;

import easytcp.model.CaptureStatus;
import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.view.ArrowDiagram;
import easytcp.view.PacketLog;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.concurrent.Executors;

/* View class representing the options box, on the right of the arrows diagram of the EasyTCP frame.
 */
public class OptionsPanel {
  private static final Logger LOGGER = LoggerFactory.getLogger(OptionsPanel.class);
  private final JPanel containerPanel;
  private final MiddleRow middleRow;
  private final FiltersForm filtersForm;
  private final PacketLog packetLog;
  private final HashMap<String, PcapNetworkInterface> deviceNetworkInterfaceHashMap = new HashMap<>();
  private final CaptureDescriptionPanel captureDescriptionPanel;
  private JCheckBox ipv6Checkbox;
  private JCheckBox ipv4Checkbox;
  private JCheckBox resolveHostnames;
  private JCheckBox showAckAndSequenceNumbers;
  private JCheckBox showHeaderFlags;
  private JCheckBox showWindowSize;
  private JCheckBox showLength;
  private JCheckBox showTcpOptions;


  public OptionsPanel(FiltersForm filtersForm, PacketLog packetLog) {
    this.containerPanel = createContainerPanel();
    this.packetLog = packetLog;
    this.captureDescriptionPanel= new CaptureDescriptionPanel(this.packetLog.getCaptureData());
    this.filtersForm = filtersForm;
    var topRow = createTopRowPanel();
    containerPanel.add(topRow);
    this.middleRow = createMiddleRow(containerPanel);
    createBottomRow(containerPanel);
  }

  private JPanel createTopRowPanel() {
    //creates the JPanel for the first row
    var topRow = new JPanel();
    var topRowLayout = new GridLayout();
    topRowLayout.setRows(1);
    topRowLayout.setColumns(4);
    topRowLayout.setVgap(10);
    topRowLayout.setHgap(5);
    topRow.setLayout(topRowLayout);
    addFilters(topRow);
    return topRow;
  }

  private MiddleRow createMiddleRow(JPanel container) {
    var mr = new MiddleRow(filtersForm);
    mr.setConnectionStatusLabel(CaptureData.getInstance());

    var middleRowConstraints = new GridBagConstraints();
    middleRowConstraints.gridx = 0;
    middleRowConstraints.gridy = 1;
    middleRowConstraints.fill = GridBagConstraints.BOTH;
    middleRowConstraints.weighty = 0.6;
    middleRowConstraints.weightx = 1;
    middleRowConstraints.ipadx = 10;
    middleRowConstraints.ipady = 10;
    container.add(mr.getPanel(), middleRowConstraints);
    return mr;
  }

  private void createBottomRow(JPanel container) {
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

    container.add(bottomRow, bottomRowConstraints);
  }

  private JPanel createContainerPanel() {
    var panel = new JPanel();
    var layout = new GridBagLayout();
    var containerConstraints = new GridBagConstraints();
    containerConstraints.weighty = 0.1;
    containerConstraints.weightx = 0.5;
    containerConstraints.gridx = 3;
    containerConstraints.gridy = 1;
    containerConstraints.gridheight = 1;
    containerConstraints.gridwidth = 2;
    containerConstraints.anchor = GridBagConstraints.ABOVE_BASELINE;
    layout.setConstraints(panel, containerConstraints);
    panel.setLayout(layout);
    return panel;
  }

  private void addButtons(JPanel row) {
    var defaultsBt = new JButton("Restore defaults");
    row.add(captureDescriptionPanel.getDescriptionPanel());
    defaultsBt.setSize(200, 200);
    row.add(defaultsBt);
    defaultsBt.addActionListener(event ->
      SwingUtilities.invokeLater(() -> {
        this.filtersForm.restoreDefaults();
        this.middleRow.resetConnectionInformation();
        ArrowDiagram.getInstance().setTcpConnection(null, filtersForm);
        restoreFilters();
      })
    );
    var filterBt = new JButton("Filter");
    filterBt.setName("filter");
    filterBt.setSize(200, 200);

    filterBt.addActionListener(event -> {
      this.packetLog.refilterPackets();
      middleRow.setConnectionInformation(filtersForm.getSelectedConnection());
      captureDescriptionPanel.updateCaptureStats(this.packetLog.getCaptureData());
      middleRow.setConnectionStatusLabel(this.packetLog.getCaptureData());
    }
    );
    row.add(filterBt);
  }

  /* Creates the top row filters
   */
  private void addFilters(JPanel topRow) {
    var checkboxLayout = new GridLayout();
    checkboxLayout.setColumns(1);
    checkboxLayout.setRows(4);

    // Creates two checkbox containers which are side by side,
    // which contain checkboxes for the different filters.
    var checkboxContainer = new JPanel();
    checkboxContainer.setLayout(checkboxLayout);

    resolveHostnames = new JCheckBox();
    resolveHostnames.setText("Resolve hostnames");
    resolveHostnames.setSelected(filtersForm.isResolveHostnames());
    resolveHostnames.addChangeListener((changeEvent) -> this.filtersForm.setResolveHostnames(resolveHostnames.isSelected()));
    checkboxContainer.add(resolveHostnames);

    ipv4Checkbox = new JCheckBox();
    ipv4Checkbox.setText("IPv4");
    ipv4Checkbox.addChangeListener((changeEvent) -> this.filtersForm.setShowIpv4(ipv4Checkbox.isSelected()));
    ipv4Checkbox.setSelected(filtersForm.isShowIpv4());
    checkboxContainer.add(ipv4Checkbox);

    ipv6Checkbox = new JCheckBox();
    ipv6Checkbox.setText("IPv6");
    ipv6Checkbox.setSelected(filtersForm.isShowIpv6());
    ipv6Checkbox.addChangeListener((changeEvent) -> this.filtersForm.setShowIpv6(ipv6Checkbox.isSelected()));
    checkboxContainer.add(ipv6Checkbox);

    var checkboxLayout2 = new GridLayout();
    checkboxLayout2.setColumns(1);
    checkboxLayout2.setRows(4);
    var checkboxContainer2 = new JPanel();
    checkboxContainer2.setLayout(checkboxLayout2);

    showAckAndSequenceNumbers = new JCheckBox();
    showAckAndSequenceNumbers.setText("Ack and sequence numbers");
    showAckAndSequenceNumbers.setSelected(filtersForm.isShowAckAndSeqNumbers());
    showAckAndSequenceNumbers.addChangeListener((changeEvent) -> this.filtersForm.setShowAckAndSeqNumbers(showAckAndSequenceNumbers.isSelected()));
    checkboxContainer.add(showAckAndSequenceNumbers);

    showHeaderFlags = new JCheckBox();
    showHeaderFlags.setText("Header flags");
    showHeaderFlags.setSelected(filtersForm.isShowHeaderFlags());
    showHeaderFlags.addChangeListener((changeEvent) -> this.filtersForm.setShowHeaderFlags(showHeaderFlags.isSelected()));
    checkboxContainer2.add(showHeaderFlags);

    showWindowSize = new JCheckBox();
    showWindowSize.setText("Show window size");
    showWindowSize.setSelected(filtersForm.isShowWindowSize());
    showWindowSize.addChangeListener((changeEvent) -> this.filtersForm.setShowWindowSize(showWindowSize.isSelected()));
    checkboxContainer2.add(showWindowSize);

    showLength = new JCheckBox();
    showLength.setText("Payload length");
    showLength.setSelected(filtersForm.isShowLength());
    showLength.addChangeListener((changeEvent) -> this.filtersForm.setShowLength(showLength.isSelected()));
    checkboxContainer2.add(showLength);

    showTcpOptions = new JCheckBox();
    showTcpOptions.setText("Tcp options");
    showTcpOptions.setSelected(filtersForm.isShowTcpOptions());
    showTcpOptions.addChangeListener((changeEvent) -> this.filtersForm.setShowTcpOptions(showTcpOptions.isSelected()));
    checkboxContainer2.add(showTcpOptions);

    try {
      //calls pcap4j to find all the device network interfaces
      Pcaps.findAllDevs()
        .forEach(pcapNetworkInterface ->
          //description is more human readable than name
          deviceNetworkInterfaceHashMap.put(pcapNetworkInterface.getDescription(), pcapNetworkInterface));
    } catch (PcapNativeException e) {
      LOGGER.debug("Could not find all network interfaces");
    }
    var interfaceSelect = deviceNetworkInterfaceHashMap.keySet().toArray();

    //creates interface selector
    var interfaceList = new JComboBox<>(interfaceSelect);
    this.filtersForm.setSelectedInterface(
      deviceNetworkInterfaceHashMap.get(interfaceList.getSelectedItem()));
    interfaceList.addActionListener(event -> {
      interfaceList.getSelectedItem();
      this.filtersForm.setSelectedInterface(
        deviceNetworkInterfaceHashMap.get(interfaceList.getSelectedItem()));
    });

    //creates the container for start capture and interface selector.
    var buttonContainer = new JPanel();
    var buttonLayout = new GridLayout();
    buttonLayout.setColumns(1);
    buttonLayout.setRows(2);
    buttonContainer.setLayout(buttonLayout);
    buttonContainer.add(interfaceList);
    buttonContainer.add(getStartLiveCaptureButton(interfaceList));
    topRow.add(checkboxContainer);
    topRow.add(checkboxContainer2);
    topRow.add(buttonContainer);
  }

  public void restoreFilters() {
    // restores the default filters for the top row
    SwingUtilities.invokeLater(() -> {
      ipv4Checkbox.setSelected(filtersForm.isShowIpv4());
      ipv6Checkbox.setSelected(filtersForm.isShowIpv6());
      resolveHostnames.setSelected(filtersForm.isResolveHostnames());
      showWindowSize.setSelected(filtersForm.isShowWindowSize());
      showLength.setSelected(filtersForm.isShowWindowSize());
      showHeaderFlags.setSelected(filtersForm.isShowHeaderFlags());
      showAckAndSequenceNumbers.setSelected(filtersForm.isShowAckAndSeqNumbers());
      showTcpOptions.setSelected(filtersForm.isShowTcpOptions());
      containerPanel.repaint();
      containerPanel.revalidate();
    });
  }

  //creates the start live capture button
  private JButton getStartLiveCaptureButton(JComboBox interfaceSelect) {
    var button = new JButton("Start capture");
    button.addActionListener(event -> {
      //gets the network interface from the selector
      var networkInterface = deviceNetworkInterfaceHashMap.get((String) interfaceSelect.getSelectedItem());
      if (networkInterface != null) {
        //starts live capture o na separate thread, to not hang the UI thread
        var executor = Executors.newSingleThreadExecutor();
        executor.execute(
          () -> {
            try {
              packetLog.startPacketCapture(
                networkInterface, this);
              SwingUtilities.invokeLater(() -> {
                if (ApplicationStatus.getStatus().isLiveCapturing().get()
                  && ApplicationStatus.getStatus().getMethodOfCapture() == CaptureStatus.LIVE_CAPTURE) {
                  button.setText("Stop capture");
                } else {
                  button.setText("Start capture");
                }
              });
            } catch (Exception e) {
              LOGGER.error(e.getMessage());
              LOGGER.error("Could not start packet capture");
            }
          });
        executor.shutdown();
      } else {
        LOGGER.error("Error reading interface.");
      }
    });
    return button;
  }

  public JPanel getPanel() {
    return containerPanel;
  }

  public CaptureDescriptionPanel getCaptureDescriptionPanel() {
    return this.captureDescriptionPanel;
  }

  public MiddleRow getMiddleRow() {
    return middleRow;
  }
}
