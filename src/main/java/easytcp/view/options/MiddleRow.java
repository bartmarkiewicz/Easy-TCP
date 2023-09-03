package easytcp.view.options;

import easytcp.model.TcpStrategyDetection;
import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.TCPConnection;
import easytcp.service.ConnectionDisplayService;
import easytcp.service.ServiceProvider;
import easytcp.view.ArrowDiagram;
import easytcp.service.DocumentUpdateListener;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;

/*
 * Class representing the middle row in the options panel
 */
public class MiddleRow {
  private static MiddleRow middleRow;
  private final JPanel middleRowPanel;
  private JTextPane connectionInformationPane;
  private JScrollPane packetViewScroll;
  private JTextPane selectedConnectionInfoPane;
  private JComboBox<TCPConnection> connectionSelector;
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
    var firstColPanel = getFirstColPanel(filtersForm);
    var middlePanel = getConnectionInfoAndSelectorContainer(filtersForm);
    var rightColumn = getRightColumnPanel(filtersForm);
    middleRowPanel.add(firstColPanel);
    middleRowPanel.add(middlePanel);
    middleRowPanel.add(rightColumn);
  }

  private JPanel getConnectionInfoAndSelectorContainer(FiltersForm filtersForm) {
    var connectionSelectorPanel = new JPanel();
    connectionSelectorPanel.setLayout(new BorderLayout());
    model = new DefaultComboBoxModel<>();
    connectionSelector = new JComboBox<>(model);
    connectionSelector.setName("connectionSelector");
    addConnectionSelector(connectionSelectorPanel, filtersForm);
    var connectionInfoAndSelectorContainer = new JPanel();
    var borderLayout = new BorderLayout();
    connectionInfoAndSelectorContainer.setLayout(borderLayout);
    connectionInfoAndSelectorContainer.add(connectionSelectorPanel, BorderLayout.NORTH);
    selectedConnectionInfoPane = new JTextPane();
    selectedConnectionInfoPane.setText(getDefaultSelectedConnectionText());
    var scrollPane = new JScrollPane(selectedConnectionInfoPane);
    connectionInfoAndSelectorContainer.add(scrollPane, BorderLayout.CENTER);
    setConnectionStatusLabel(CaptureData.getInstance());
    return connectionInfoAndSelectorContainer;
  }

  private JPanel getFirstColPanel(FiltersForm filtersForm) {
    var firstColPanel = new JPanel();
    var firstColPanelLt = new GridLayout();
    firstColPanelLt.setColumns(1);
    firstColPanelLt.setRows(2);
    firstColPanel.setLayout(firstColPanelLt);
    connectionInformationPane = new JTextPane();
    connectionInformationPane.setName("connectionsInformation");
    packetViewScroll = new JScrollPane(connectionInformationPane);
    connectionInformationPane.setEditable(false);
    connectionInformationPane.setFont(
      new Font(connectionInformationPane.getFont().getName(), Font.PLAIN, 11));
    packetViewScroll.setAutoscrolls(false);
    var connectionDescriptionSettingPanel = getConnectionDescriptionSettingPanel(filtersForm);
    firstColPanel.add(connectionDescriptionSettingPanel);
    firstColPanel.add(packetViewScroll);
    return firstColPanel;
  }

  private JPanel getConnectionDescriptionSettingPanel(FiltersForm filtersForm) {
    var connectionDescriptionSettingPanel = new JPanel();
    addConnectionDescriptionSettings(connectionDescriptionSettingPanel, filtersForm);
    return connectionDescriptionSettingPanel;
  }

  private JPanel getRightColumnPanel(FiltersForm filtersForm) {
    var rightColPanel = new JPanel();
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

    portInput.getDocument().addDocumentListener((DocumentUpdateListener) e -> filtersForm.setPortRangeSelected(portInput.getText()));

    hostInput.getDocument().addDocumentListener((DocumentUpdateListener) e -> filtersForm.setHostSelected(hostInput.getText()));

    var rightColLayout = new GridLayout();
    rightColLayout.setColumns(1);
    rightColLayout.setRows(2);
    rightColPanel.setLayout(rightColLayout);
    var connectionInformationSettingsPanel = new JPanel();
    addConnectionFeatureSettings(connectionInformationSettingsPanel, filtersForm);
    rightColPanel.add(connectionInformationSettingsPanel);
    inputFieldsContainer.add(portContainer);
    inputFieldsContainer.add(hostContainer);
    rightColPanel.add(inputFieldsContainer);
    return rightColPanel;
  }

  private String getDefaultSelectedConnectionText() {
    return "Select a connection to view information about it.";
  }

  private void addConnectionDescriptionSettings(JPanel connectionDescriptionSettingPanel, FiltersForm filtersForm) {
    var layout = new GridLayout();
    layout.setRows(2);
    connectionDescriptionSettingPanel.setLayout(layout);
    var showTcpFeatures = new JCheckBox("Show detected tcp features");
    showTcpFeatures.addChangeListener((i) -> filtersForm.setShowTcpFeatures(showTcpFeatures.isSelected()));
    var showGeneralConnectionInformation = new JCheckBox("Show general information");
    showTcpFeatures.addChangeListener((i) -> filtersForm.setShowGeneralInformation(showGeneralConnectionInformation.isSelected()));
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


  /* Sets up the connection selector
   */
  private void addConnectionSelector(JPanel connectionSelectorPanel, FiltersForm filtersForm) {
    connectionSelector.setFont(new Font(connectionSelector.getFont().getName(), Font.PLAIN, 10));
    connectionSelector.setLightWeightPopupEnabled(false);
    connectionSelector.setToolTipText("Select a TCP connection");
    connectionSelectorPanel.add(new JLabel("Connection"), BorderLayout.NORTH);
    connectionSelectorPanel.add(connectionSelector, BorderLayout.CENTER);

    connectionSelector.addItemListener((i) -> {
      if (i.getStateChange() == ItemEvent.SELECTED
        && (connectionSelector.getSelectedItem() != null &&
              !connectionSelector.getSelectedItem().equals(filtersForm.getSelectedConnection()))) {
        //different connection selected
          var selectedItem = (TCPConnection) connectionSelector.getSelectedItem();
          filtersForm.setSelectedConnection(selectedItem);
          ArrowDiagram.getInstance().setTcpConnection(selectedItem, filtersForm);
      } else {
        //once the connectionSelector is updated, repaints the arrow diagram
        SwingUtilities.invokeLater(() -> {
          ArrowDiagram.getInstance().revalidate();
          ArrowDiagram.getInstance().repaint();
        });
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

  /* Adds new connections captured to the connection selector
   */
  public synchronized void addConnectionOptions(CaptureData captureData) {
    var connections = new ArrayList<>(captureData.getTcpConnectionMap().values());
    if (model.getSize() != connections.size()) {
      model.removeAllElements();

      model.addAll(new ArrayList<>(captureData.getTcpConnectionMap()
        .values())
        .stream()
        .filter(Objects::nonNull)
        .sorted(Comparator.comparing((TCPConnection con) -> con.getPacketContainer().getPackets().size())
                .reversed())
        .toList());
      var ff = FiltersForm.getInstance();
      model.setSelectedItem(ff.getSelectedConnection());
      SwingUtilities.invokeLater(() -> {
        connectionSelector.repaint();
        connectionSelector.revalidate();
        ArrowDiagram.getInstance().repaint();
        ArrowDiagram.getInstance().revalidate();
      });
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
      var connectionDisplayThread = Executors.newSingleThreadExecutor();
      connectionDisplayThread.execute(() -> {
        //getting connection information is a heavy operation, so should be done on a seperate thread
        var connectionDisplayInformation = connectionDisplayService.getConnectionInformation(FiltersForm.getInstance().getSelectedConnection());
        SwingUtilities.invokeLater(() -> {
          selectedConnectionInfoPane.setText(connectionDisplayInformation);
          selectedConnectionInfoPane.repaint();
          selectedConnectionInfoPane.revalidate();
        });
      });
    } else {
      selectedConnectionInfoPane.setText(getDefaultSelectedConnectionText());
      selectedConnectionInfoPane.repaint();
      selectedConnectionInfoPane.revalidate();
    }
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
      if (selectedConnection != null) {
        selectedConnectionInfoPane.setText(connectionDisplayService.getConnectionInformation(selectedConnection));
        selectedConnectionInfoPane.repaint();
        selectedConnectionInfoPane.revalidate();
        ArrowDiagram.getInstance().repaint();
        ArrowDiagram.getInstance().revalidate();
      }
    });
    connectionSelector.repaint();
    connectionSelector.revalidate();
  }
}
