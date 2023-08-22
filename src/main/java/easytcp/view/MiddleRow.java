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
    var middleRowLayout = new GridLayout();
    middleRowLayout.setRows(1);
    middleRowLayout.setColumns(3);
    middleRowPanel.setLayout(middleRowLayout);
    var firstColPanel = new JPanel();
    var firstColPanelLt = new GridLayout();
    firstColPanelLt.setColumns(1);
    firstColPanelLt.setRows(2);
    firstColPanel.setLayout(firstColPanelLt);
    connectionInformationPane = new JTextPane();
    packetViewScroll = new JScrollPane(connectionInformationPane);
    connectionInformationPane.setEditable(false);
    connectionInformationPane.setFont(
      new Font(connectionInformationPane.getFont().getName(), Font.PLAIN, 11));
    packetViewScroll.setAutoscrolls(false);

    var connectionSelectorPanel = new JPanel();
    connectionSelectorPanel.setLayout(new BorderLayout());
    model = new DefaultComboBoxModel<>();
    connectionSelector = new JComboBox<>(model);
    addConnectionSelector(connectionSelectorPanel, filtersForm);
    var connectionInfoAndSelectorContainer = new JPanel();
    var borderLayout = new BorderLayout();
    connectionInfoAndSelectorContainer.setLayout(borderLayout);
    connectionInfoAndSelectorContainer.add(connectionSelectorPanel, BorderLayout.NORTH);
    selectedConnectionInfoPane = new JTextPane();
    selectedConnectionInfoPane.setText(getDefaultSelectedConnectionText());
    var scrollPane = new JScrollPane(selectedConnectionInfoPane);
    connectionInfoAndSelectorContainer.add(scrollPane, BorderLayout.CENTER);
    setConnectionStatusLabel(CaptureData.getCaptureData());
    var connectionInformationSettingsPanel = new JPanel();
    addConnectionFeatureSettings(connectionInformationSettingsPanel, filtersForm);
    var inputFieldsContainer = new JPanel();
    var inputFieldsLayout = new GridLayout();
    inputFieldsLayout.setRows(2);
    inputFieldsLayout.setColumns(1);
    inputFieldsContainer.setLayout(inputFieldsLayout);
    var portContainer = new JPanel();
    var rowLayout = new BorderLayout();
    var rowLayout2 = new BorderLayout();
    portContainer.setLayout(rowLayout);
    var hostContainer = new JPanel();
    hostContainer.setLayout(rowLayout2);
    portInput = new JTextField();
    var portLabel = new JLabel("Port");
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
    var rightColumn = new JPanel();
    var rightColLayout = new GridLayout();
    rightColLayout.setColumns(1);
    rightColLayout.setRows(2);
    rightColumn.setLayout(rightColLayout);
    rightColumn.add(connectionInformationSettingsPanel);
    inputFieldsContainer.add(portContainer);
    inputFieldsContainer.add(hostContainer);
    rightColumn.add(inputFieldsContainer);
    firstColPanel.add(connectionDescriptionSettingPanel);
//    firstColPanel.add(connectionInformationSettingsPanel);
    firstColPanel.add(packetViewScroll);
    middleRowPanel.add(firstColPanel);
    middleRowPanel.add(connectionInfoAndSelectorContainer);
    middleRowPanel.add(rightColumn);
  }

  private String getDefaultSelectedConnectionText() {
    return "Select a connection to view information about it.";
  }

  private void addConnectionDescriptionSettings(JPanel connectionDescriptionSettingPanel, FiltersForm filtersForm) {
    var layout = new GridLayout();
    layout.setRows(2);
    connectionDescriptionSettingPanel.setLayout(layout);
    var showTcpFeatures = new JCheckBox("Show detected tcp features");
    showTcpFeatures.addChangeListener((i) -> {
      filtersForm.setShowTcpFeatures(showTcpFeatures.isSelected());
    });
    var showGeneralConnectionInformation = new JCheckBox("Show general information");
    showTcpFeatures.addChangeListener((i) -> {
      filtersForm.setShowGeneralInformation(showGeneralConnectionInformation.isSelected());
    });
    showGeneralConnectionInformation.setSelected(false);

    showTcpFeatures.setSelected(true);
    connectionDescriptionSettingPanel.add(showTcpFeatures);
    connectionDescriptionSettingPanel.add(showGeneralConnectionInformation);
  }

  private void addConnectionFeatureSettings(JPanel connectionInformationSettingsPanel, FiltersForm filtersForm) {
    var layout = new BoxLayout(connectionInformationSettingsPanel, BoxLayout.Y_AXIS);
    connectionInformationSettingsPanel.setLayout(layout);
    var radioOptions = new ButtonGroup();
    var label = new JLabel("Feature detection sensitivity");
    var labelContainer = new JPanel();
    labelContainer.setLayout(new GridLayout());
    labelContainer.add(label);
    connectionInformationSettingsPanel.add(labelContainer);

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
    var container = new JPanel();
    container.setLayout(new BoxLayout(container, BoxLayout.X_AXIS));
    container.add(highThreshold);
    container.add(mediumThreshold);
    container.add(lowThreshold);
    connectionInformationSettingsPanel.add(container);
  }

  public JPanel getPanel() {
    return middleRowPanel;
  }

  private void addConnectionSelector(JPanel connectionSelectorPanel, FiltersForm filtersForm) {
    connectionSelector.setFont(new Font(connectionSelector.getFont().getName(), 5, 10));
    connectionSelector.setLightWeightPopupEnabled(false);
    connectionSelector.setToolTipText("Select a TCP connection");
    connectionSelectorPanel.add(new JLabel("Connection"), BorderLayout.NORTH);
    connectionSelectorPanel.add(connectionSelector, BorderLayout.CENTER);

    connectionSelector.addItemListener((i) -> {
      if (i.getStateChange() == ItemEvent.SELECTED || i.getStateChange() == ItemEvent.DESELECTED) {
          var selectedItem = (TCPConnection) connectionSelector.getSelectedItem();
          filtersForm.setSelectedConnection(selectedItem);
          ArrowDiagram.getInstance().setTcpConnection(selectedItem, filtersForm);
      }
    });
  }

  public void resetConnectionInformation() {
    selectedConnectionInfoPane.setText("Select a connection to view information about it.");
    model.setSelectedItem(null);
    portInput.setText("");
    hostInput.setText("");
    selectedConnectionInfoPane.revalidate();
    selectedConnectionInfoPane.repaint();
  }

  public synchronized void addConnectionOptions(CaptureData captureData) {
    var connections = new ArrayList<>(captureData.getTcpConnectionMap().values());
    if (model.getSize() != connections.size()) {
      model.removeAllElements();

      model.addAll(new ArrayList<>(captureData.getTcpConnectionMap()
        .values())
        .stream()
        .filter(Objects::nonNull)
        .toList());
      var ff = FiltersForm.getFiltersForm();
      model.setSelectedItem(ff.getSelectedConnection());

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
    if (FiltersForm.getInstance().getSelectedConnection() != null) {
      selectedConnectionInfoPane.setText(connectionDisplayService.getConnectionInformation(FiltersForm.getFiltersForm().getSelectedConnection()));
    } else {
      selectedConnectionInfoPane.setText(getDefaultSelectedConnectionText());
    }
    selectedConnectionInfoPane.repaint();
    selectedConnectionInfoPane.revalidate();
    packetViewScroll.repaint();
    packetViewScroll.revalidate();
    addConnectionOptions(captureData);
  }

  public static MiddleRow getInstance() {
    if (middleRow == null) {
      middleRow = new MiddleRow(FiltersForm.getInstance());
      return middleRow;
    }
    return middleRow;
  }

  public void setConnectionInformation(TCPConnection selectedConnection) {
    model.setSelectedItem(selectedConnection);
    SwingUtilities.invokeLater(() -> {
      selectedConnectionInfoPane.setText(connectionDisplayService.getConnectionInformation(selectedConnection));
      selectedConnectionInfoPane.revalidate();
      selectedConnectionInfoPane.repaint();
    });
    connectionSelector.revalidate();
    connectionSelector.repaint();
  }
}
