package easytcp.view;

import easytcp.model.application.CaptureData;
import easytcp.model.application.FiltersForm;
import easytcp.model.packet.ConnectionStatus;
import easytcp.model.packet.TCPConnection;

import javax.swing.*;
import java.awt.*;
import java.util.Set;

public class MiddleRow {
  private final JPanel middleRowPanel;
  private final JTextPane connectionInformationPane;
  private final JScrollPane packetViewScroll;
  private DefaultComboBoxModel<TCPConnection> model;

  public MiddleRow(FiltersForm filtersForm) {
    this.middleRowPanel = new JPanel();
    middleRowPanel.setBackground(Color.YELLOW);
    var middleRowLayout = new GridBagLayout();
    var middleRowConstraints = new GridBagConstraints();
//    middleRowConstraints.fill = GridBagConstraints.BOTH;
//    middleRowConstraints.weighty = 1;
//    middleRowConstraints.gridheight = 6;
//    middleRowConstraints.gridwidth = 6;
//    middleRowConstraints.weightx = 1;

//    middleRowLayout.setConstraints(middleRowPanel, middleRowConstraints);
//    middleRowLayout.setColumns(2);
//    middleRowLayout.setRows(1);
    var leftPaneConstraints = new GridBagConstraints();
    leftPaneConstraints.weighty = 0.5;
    leftPaneConstraints.weightx = 0.2;
    leftPaneConstraints.gridx = 0;
    leftPaneConstraints.gridheight = 2;
    leftPaneConstraints.gridwidth = 2;
    leftPaneConstraints.gridy = 0;
    leftPaneConstraints.fill = GridBagConstraints.BOTH;
//    middleRowLayout.setConstraints(middleRowPanel);
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
    addConnectionSelector(connectionSelectorPanel);
    var connectionSelectorConstraints = new GridBagConstraints();
    connectionSelectorConstraints.weighty = 0;
    connectionSelectorConstraints.weightx = 0.5;
    connectionSelectorConstraints.gridx = 3;
    connectionSelectorConstraints.gridy = 0;
    connectionSelectorConstraints.gridheight = 1;
    connectionSelectorConstraints.gridwidth = 4;
    connectionSelectorConstraints.anchor = GridBagConstraints.ABOVE_BASELINE;
    connectionSelectorConstraints.fill = GridBagConstraints.HORIZONTAL;
    middleRowPanel.add(connectionSelectorPanel, connectionSelectorConstraints);
    var connectionInfoPane = new JTextPane();
    connectionInfoPane.setText("Selected connection info here - \n lolol \n test");

    var connectionInfoConstraints = new GridBagConstraints();
    connectionInfoConstraints.weighty = 0.1;
    connectionInfoConstraints.weightx = 0.5;
    connectionInfoConstraints.gridx = 3;
    connectionInfoConstraints.gridy = 1;
    connectionInfoConstraints.gridheight = 1;
    connectionInfoConstraints.gridwidth = 2;
    connectionInfoConstraints.anchor = GridBagConstraints.ABOVE_BASELINE;

    connectionInfoConstraints.fill = GridBagConstraints.BOTH;

    middleRowPanel.add(connectionInfoPane, connectionInfoConstraints);

    setConnectionStatusLabel(CaptureData.getCaptureData());

    var inputFieldsContainer = new JPanel();
    var inputFieldsLayout = new GridLayout();
    inputFieldsLayout.setRows(3);
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
      filtersForm.setPortRangeSelected(portInput.getText());
    });

    hostInput.getDocument().addDocumentListener((DocumentUpdateListener) e -> {
      filtersForm.setHostSelected(hostInput.getText());
    });
    inputFieldsContainer.add(new JPanel());
    inputFieldsContainer.add(portContainer);
    inputFieldsContainer.add(hostContainer);
    var inputFieldsConstraints = new GridBagConstraints();
    inputFieldsConstraints.weighty = 0.5;
    inputFieldsConstraints.weightx = 0.5;
    inputFieldsConstraints.gridx = 5;
    inputFieldsConstraints.gridy = 0;
    inputFieldsConstraints.gridwidth = 2;
    inputFieldsConstraints.gridheight = 2;
    inputFieldsConstraints.fill = GridBagConstraints.BOTH;
    middleRowPanel.add(inputFieldsContainer, inputFieldsConstraints);

  }

  public JPanel getPanel() {
    return middleRowPanel;
  }

  private void addConnectionSelector(JPanel connectionSelectorPanel) {
    model = new DefaultComboBoxModel<>();
    var connectionSelector = new JComboBox<>(model);
    connectionSelectorPanel.setBackground(Color.CYAN);
    connectionSelector.setFont(new Font(connectionSelector.getFont().getName(), 5, 10));
    connectionSelector.setLightWeightPopupEnabled(true);
    connectionSelector.setToolTipText("Select a TCP connection");
    connectionSelectorPanel.add(new JLabel("Connection"), BorderLayout.NORTH);
    connectionSelectorPanel.add(connectionSelector, BorderLayout.CENTER);
  }

  public void addConnectionOptions(CaptureData captureData) {
    model.addAll(captureData.getTcpConnectionMap().values());
  }

  public void setConnectionStatusLabel(CaptureData captureData) {
    connectionInformationPane.setText("""
    TCP connections
    %s with status SYN_SENT
    %s with status SYN_RCVD
    %s with status ESTABLISHED
    %s with status FIN_WAIT_1
    %s with status FIN_WAIT_2
    %s with status LAST_ACK
    %s with status TIME_WAIT
    %s with status CLOSE_WAIT
    %s with status CLOSED
    %s with status UNKNOWN
    """.formatted(
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.SYN_SENT)).size(),
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.SYN_RECEIVED)).size(),
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.ESTABLISHED)).size(),
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.FIN_WAIT_1)).size(),
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.FIN_WAIT_2)).size(),
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.LAST_ACK)).size(),
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.TIME_WAIT)).size(),
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.CLOSE_WAIT)).size(),
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.CLOSED)).size(),
      captureData.getTcpConnectionsWithStatus(Set.of(ConnectionStatus.UNKNOWN)).size()
    ));
    connectionInformationPane.setCaretPosition(100);
    connectionInformationPane.revalidate();
    connectionInformationPane.repaint();
    packetViewScroll.repaint();
    packetViewScroll.revalidate();
    addConnectionOptions(captureData);
  }
}
