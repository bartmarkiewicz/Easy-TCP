package easytcp.view;

import easytcp.model.application.FiltersForm;
import easytcp.service.ServiceProvider;

import javax.swing.*;
import java.awt.*;

public class EasyTCP extends JFrame {
    public EasyTCP() {
        super();
        this.setTitle("Easy TCP");
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        screenSize.setSize(screenSize.width - 120, screenSize.height - 120);
        this.setPreferredSize(screenSize);
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            System.out.println("Error setting default windows styling, defaulting to swing styling.");
        }
        initComponents();
    }

    private void initComponents() {
        GridLayout parentLayout = getGridLayout();
        this.getContentPane().setLayout(parentLayout);
        JPanel firstRow = new JPanel();
        GridLayout firstRowLayout = new GridLayout();
        firstRowLayout.setRows(1);
        firstRowLayout.setVgap(25);
        firstRowLayout.setHgap(25);
        firstRowLayout.setColumns(2);
        firstRow.setLayout(firstRowLayout);
        var arrowDiagram = ArrowDiagram.getInstance();
        var arrowDiagramScrollPane = new JScrollPane(arrowDiagram);
        arrowDiagram.setScrollPane(arrowDiagramScrollPane);
        firstRow.add(arrowDiagramScrollPane);
        var filtersForm = FiltersForm.getInstance();
        var packetLogger = new PacketLog(filtersForm, ServiceProvider.getInstance());

        var optionsPanel = new OptionsPanel(filtersForm, packetLogger);
        firstRow.add(optionsPanel.getPanel());

        this.getContentPane().add(firstRow);

        packetLogger.getPacketTextPane().setBackground(Color.PINK);
        var packetViewScroll = new JScrollPane(packetLogger.getPacketTextPane());

        packetViewScroll.setVerticalScrollBarPolicy(JScrollPane. VERTICAL_SCROLLBAR_AS_NEEDED);
        packetViewScroll.setBackground(Color.pink);

        var menuToolbar = new MenuToolbar();
        menuToolbar.addNewMenuItemListener((actionEvent) -> {
            packetLogger.newLog();
        });
        var fileChooser = new JFileChooser();
        fileChooser.addActionListener(actionEvent -> {
            var fileSelected = fileChooser.getSelectedFile();
            try {
                packetLogger.readSelectedFile(fileSelected, optionsPanel);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(
                  this, "Error, invalid file. " +
                    "Please select a valid packet capture file.");
            }
        });

        menuToolbar.addOpenMenuItemListener(actionEvent -> {
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            fileChooser.showOpenDialog(this);
            fileChooser.setMultiSelectionEnabled(false);
        });

        this.setJMenuBar(menuToolbar.getMenuBar());

        this.getContentPane().add(packetViewScroll);
        this.setVisible(true);
    }

    private GridLayout getGridLayout() {
        GridLayout layout = new GridLayout();
        layout.setRows(2);
        layout.setColumns(1);
        return layout;
    }
}
