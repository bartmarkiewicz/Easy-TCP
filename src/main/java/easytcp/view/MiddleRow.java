package easytcp.view;

import easytcp.model.TcpStrategyDetection;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.TCPConnection;
import easytcp.service.ConnectionDisplayService;
import easytcp.service.ServiceProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;

public class MiddleRow {
  private static MiddleRow middleRow;
  private final JPanel middleRowPanel;
  private final JTextPane connectionInformationPane;
  private final JScrollPane packetViewScroll;
  private final JTextPane selectedConnectionInfoPane;
  private final JComboBox<TCPConnection> connectionSelector;
  private final ConnectionDisplayService connectionDisplayService;
  private JTextField hostInput;
  private JTextField portInput;

  private DefaultComboBoxModel<TCPConnection> model;

  public MiddleRow(FiltersForm filtersForm) {
    this.middleRowPanel = new JPanel();
    connectionDisplayService = ServiceProvider.getInstance().getConnectionDisplayService();
    middleRowPanel.setBackground(Color.YELLOW);
    var middleRowLayout = new GridBagLayout();
    var leftPaneConstraints = new GridBagConstraints();
    leftPaneConstraints.weighty = 0.5;
    leftPaneConstraints.weightx = 0.3;
    leftPaneConstraints.gridx = 0;
    leftPaneConstraints.gridheight = 2;
    leftPaneConstraints.gridwidth = 2;
    leftPaneConstraints.gridy = 0;
    leftPaneConstraints.fill = GridBagConstraints.BOTH;
    middleRowPanel.setLayout(middleRowLayout);
    connectionInformationPane = new JTextPane();
    packetViewScroll = new JScrollPane(connectionInformationPane);
    connectionInformationPane.setEditable(false);
    connectionInformationPane.setFont(
      new Font(connectionInformationPane.getFont().getName(), Font.PLAIN, 11));
    packetViewScroll.setAutoscrolls(false);
    middleRowPanel.add(packetViewScroll, leftPaneConstraints);
    var connectionSelectorPanel = new JPanel();
    connectionSelectorPanel.setLayout(new BorderLayout());
    model = new DefaultComboBoxModel<>();
    connectionSelector = new JComboBox<>(model);
    addConnectionSelector(connectionSelectorPanel, filtersForm);
    var connectionSelectorConstraints = new GridBagConstraints();
    connectionSelectorConstraints.weighty = 0;
    connectionSelectorConstraints.weightx = 0.3;
    connectionSelectorConstraints.gridx = 3;
    connectionSelectorConstraints.gridy = 0;
    connectionSelectorConstraints.gridheight = 1;
    connectionSelectorConstraints.gridwidth = 4;
    connectionSelectorConstraints.anchor = GridBagConstraints.ABOVE_BASELINE;
    connectionSelectorConstraints.fill = GridBagConstraints.HORIZONTAL;
    middleRowPanel.add(connectionSelectorPanel, connectionSelectorConstraints);
    selectedConnectionInfoPane = new JTextPane();
    selectedConnectionInfoPane.setText("Select a connection to view information about it.");
    var scrollPane = new JScrollPane(selectedConnectionInfoPane);
    var connectionInfoConstraints = new GridBagConstraints();
    connectionInfoConstraints.weighty = 0.1;
    connectionInfoConstraints.weightx = 0.4;
    connectionInfoConstraints.gridx = 3;
    connectionInfoConstraints.gridy = 1;
    connectionInfoConstraints.gridheight = 1;
    connectionInfoConstraints.gridwidth = 2;
    connectionInfoConstraints.anchor = GridBagConstraints.ABOVE_BASELINE;

    connectionInfoConstraints.fill = GridBagConstraints.BOTH;

    middleRowPanel.add(scrollPane, connectionInfoConstraints);

    setConnectionStatusLabel(CaptureData.getCaptureData());
    var connectionInformationSettingsPanel = new JPanel();
    addConnectionFeatureSettings(connectionInformationSettingsPanel, filtersForm);
    var conInfoPanelLt = new GridLayout();
    conInfoPanelLt.setColumns(2);
    conInfoPanelLt.setRows(1);
    var inputFieldsContainer = new JPanel();
    var inputFieldsLayout = new GridLayout();
    inputFieldsLayout.setRows(4);
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
    portInput = new JTextField();
    var portLabel = new JLabel("Port");
    portInput.add(portLabel);
    hostInput = new JTextField();
    var hostLabel = new JLabel("Host");
    hostLabel.setHorizontalAlignment(SwingConstants.RIGHT);
    portLabel.setHorizontalAlignment(SwingConstants.RIGHT);
    portContainer.add(portLabel, BorderLayout.LINE_START);
    portContainer.add(portInput, BorderLayout.CENTER);
    hostContainer.add(hostLabel, BorderLayout.LINE_START);
    hostContainer.add(hostInput, BorderLayout.CENTER);

    portInput.getDocument().addDocumentListener((DocumentUpdateListener) e -> {
      filtersForm.setPortRangeSelected(portInput.getText());
    });

    hostInput.getDocument().addDocumentListener((DocumentUpdateListener) e -> {
      filtersForm.setHostSelected(hostInput.getText());
    });
    var connectionDescriptionSettingPanel = new JPanel();
    addConnectionDescriptionSettings(connectionDescriptionSettingPanel, filtersForm);
    inputFieldsContainer.add(connectionDescriptionSettingPanel);
    inputFieldsContainer.add(connectionInformationSettingsPanel);
    inputFieldsContainer.add(portContainer);
    inputFieldsContainer.add(hostContainer);
    var inputFieldsConstraints = new GridBagConstraints();
    inputFieldsConstraints.weighty = 0.5;
    inputFieldsConstraints.weightx = 0.4;
    inputFieldsConstraints.gridx = 5;
    inputFieldsConstraints.gridy = 0;
    inputFieldsConstraints.gridwidth = 1;
    inputFieldsConstraints.gridheight = 2;
    inputFieldsConstraints.fill = GridBagConstraints.BOTH;
    middleRowPanel.add(inputFieldsContainer, inputFieldsConstraints);

  }

  private void addConnectionDescriptionSettings(JPanel connectionDescriptionSettingPanel, FiltersForm filtersForm) {
    var layout = new GridBagLayout();
    var constraints = new GridBagConstraints();
    constraints.gridheight = 3;
    constraints.gridwidth = 2;
    layout.setConstraints(connectionDescriptionSettingPanel, constraints);
    connectionDescriptionSettingPanel.setLayout(layout);
    var showTcpFeatures = new JCheckBox("Show detected tcp features");
    showTcpFeatures.addActionListener((i) -> {
      filtersForm.setShowTcpFeatures(showTcpFeatures.isSelected());
    });
    var showGeneralConnectionInformation = new JCheckBox("Show general information");
    showTcpFeatures.addActionListener((i) -> {
      filtersForm.setShowGeneralInformation(showGeneralConnectionInformation.isSelected());
    });
    var tcpFeaturesConstraints = new GridBagConstraints();
    tcpFeaturesConstraints.gridy = 3;
    tcpFeaturesConstraints.gridx = 1;
    tcpFeaturesConstraints.anchor = GridBagConstraints.SOUTH;
    showGeneralConnectionInformation.setSelected(false);
    var connectionInfoConstraints = new GridBagConstraints();
    connectionInfoConstraints.gridy = 3;
    connectionInfoConstraints.gridx = 2;
    connectionInfoConstraints.anchor = GridBagConstraints.SOUTH;
    var invisiblePanelConstraints = new GridBagConstraints();
    invisiblePanelConstraints.anchor = GridBagConstraints.NORTH;
    invisiblePanelConstraints.gridy = 0;
    invisiblePanelConstraints.weightx = 1;
    invisiblePanelConstraints.weighty = 1;
    invisiblePanelConstraints.gridx = 0;
    invisiblePanelConstraints.gridwidth = 2;
    invisiblePanelConstraints.gridheight = 3;
    showTcpFeatures.setSelected(true);
    connectionDescriptionSettingPanel.add(new JPanel(), invisiblePanelConstraints);
    connectionDescriptionSettingPanel.add(showTcpFeatures, tcpFeaturesConstraints);
    connectionDescriptionSettingPanel.add(showGeneralConnectionInformation, connectionInfoConstraints);
  }

  private void addConnectionFeatureSettings(JPanel connectionInformationSettingsPanel, FiltersForm filtersForm) {
    var layout = new BoxLayout(connectionInformationSettingsPanel, BoxLayout.X_AXIS);
    connectionInformationSettingsPanel.setLayout(layout);
    var radioOptions = new ButtonGroup();
    connectionInformationSettingsPanel.add(new JPanel());
    connectionInformationSettingsPanel.add(
      new JLabel("Feature detection sensitivity"));
    connectionInformationSettingsPanel.add(new JPanel());

    var highThreshold = new JRadioButton("Strict");
    highThreshold.addChangeListener((i) -> {
      if (highThreshold.isSelected()) {
        filtersForm.setTcpStrategyThreshold(TcpStrategyDetection.STRICT);
      }
    });

    var mediumThreshold = new JRadioButton("Balanced");
    mediumThreshold.addChangeListener((i) -> {
      if (mediumThreshold.isSelected()) {
        filtersForm.setTcpStrategyThreshold(TcpStrategyDetection.BALANCED);
      }
    });
    mediumThreshold.setSelected(true);
    var lowThreshold = new JRadioButton("Lenient");
    lowThreshold.addChangeListener((i) -> {
      if (lowThreshold.isSelected()) {
        filtersForm.setTcpStrategyThreshold(TcpStrategyDetection.LENIENT);
      }
    });
    radioOptions.add(highThreshold);
    radioOptions.add(mediumThreshold);
    radioOptions.add(lowThreshold);
    connectionInformationSettingsPanel.add(highThreshold);
    connectionInformationSettingsPanel.add(mediumThreshold);
    connectionInformationSettingsPanel.add(lowThreshold);

  }

  public JPanel getPanel() {
    return middleRowPanel;
  }

  private void addConnectionSelector(JPanel connectionSelectorPanel, FiltersForm filtersForm) {
    connectionSelectorPanel.setBackground(Color.CYAN);
    connectionSelector.setFont(new Font(connectionSelector.getFont().getName(), 5, 10));
    connectionSelector.setLightWeightPopupEnabled(false);
    connectionSelector.setToolTipText("Select a TCP connection");
    connectionSelectorPanel.add(new JLabel("Connection"), BorderLayout.NORTH);
    connectionSelectorPanel.add(connectionSelector, BorderLayout.CENTER);
    connectionSelector.addItemListener((i) -> {
      if (i.getStateChange() == ItemEvent.SELECTED
        || i.getStateChange() == ItemEvent.DESELECTED) {
          var selectedItem = (TCPConnection) connectionSelector.getSelectedItem();
          if (selectedItem != filtersForm.getSelectedConnection()) {
            ArrowDiagram.getInstance().setTcpConnection(selectedItem, filtersForm);
            if (selectedItem != null) {
              SwingUtilities.invokeLater(() -> {
                setConnectionInformation(selectedItem); }
              );
            }
            filtersForm.setSelectedConnection(selectedItem);
          }
      }
    });
  }

  public void resetConnectionInformation() {
    selectedConnectionInfoPane.setText("Select a connection to view information about it.");
    connectionSelector.setSelectedIndex(-1);
    model.setSelectedItem(null);
    portInput.setText("");
    hostInput.setText("");
    selectedConnectionInfoPane.revalidate();
    selectedConnectionInfoPane.repaint();
  }

  public void setConnectionInformation(TCPConnection selectedItem) {
    Executors.newSingleThreadExecutor().execute(() -> {
      var conInfo = connectionDisplayService.getConnectionInformation(selectedItem);
      SwingUtilities.invokeLater(() -> {
        selectedConnectionInfoPane.setText(conInfo);
        ArrowDiagram.getInstance().repaint();
        ArrowDiagram.getInstance().revalidate();
        selectedConnectionInfoPane.revalidate();
        selectedConnectionInfoPane.repaint();
      });
    });
  }

  public synchronized void addConnectionOptions(CaptureData captureData) {
    var selectedItem = (TCPConnection) connectionSelector.getSelectedItem();
    var connections = new ArrayList<>(captureData.getTcpConnectionMap().values());
    if (model.getSize() != connections.size()) {
      new ArrayList<>(captureData.getTcpConnectionMap()
        .values())
        .stream()
        .filter(Objects::nonNull)
        .forEach(i -> {
          if (model.getIndexOf(i) == -1) {
            model.addElement(i);
          }
        });
      model.setSelectedItem(selectedItem);
    }
  }

  public void setConnectionStatusLabel(CaptureData captureData) {
    var sb = new StringBuilder();
    sb.append("TCP connections\n");
    for(ConnectionStatus status: ConnectionStatus.values()) {
      var statusCount = captureData.getTcpConnectionsWithStatus(Set.of(status)).size();
      if (statusCount > 0) {
        sb.append("%s status %s\n"
          .formatted(
            statusCount,
            status.name()));
      }
    }
    connectionInformationPane.setText(sb.toString());
    connectionInformationPane.revalidate();
    connectionInformationPane.repaint();
    packetViewScroll.repaint();
    packetViewScroll.revalidate();
    if (connectionSelector.getSelectedItem() != null) {
      setConnectionInformation((TCPConnection) connectionSelector.getSelectedItem());
    }
    addConnectionOptions(captureData);
  }

  public static MiddleRow getInstance() {
    if (middleRow == null) {
      middleRow = new MiddleRow(FiltersForm.getInstance());
      return middleRow;
    }
    return middleRow;
  }

  public void setConnectionSelector(TCPConnection tcpConnectionOfPacket) {
//    addConnectionOptions(CaptureData.getCaptureData());
    connectionSelector.setSelectedItem(tcpConnectionOfPacket);
    connectionSelector.repaint();
    connectionSelector.revalidate();
  }
}
