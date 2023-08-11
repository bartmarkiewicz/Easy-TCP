package view;

import controller.FiltersForm;
import controller.PacketLogger;

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
        firstRowLayout.setColumns(2);
        firstRow.setLayout(firstRowLayout);
        ArrowDiagram arrowDiagram = new ArrowDiagram();
        firstRow.add(arrowDiagram);
        var filtersForm = new FiltersForm();
        OptionsPanel optionsPanel = new OptionsPanel(filtersForm);
        optionsPanel.setBackground(Color.BLUE);
        firstRow.add(optionsPanel);

        this.getContentPane().add(firstRow);

        var packetLogger = new PacketLogger();
        packetLogger.setBackground(Color.PINK);
        var packetViewScroll = new JScrollPane(packetLogger);

        packetViewScroll.setVerticalScrollBarPolicy(JScrollPane. VERTICAL_SCROLLBAR_AS_NEEDED);
        packetViewScroll.setBackground(Color.pink);

        var menuToolbar = new MenuToolbar();
        menuToolbar.setVisible(true);
        menuToolbar.addNewMenuItemListener((actionEvent) -> {
            packetLogger.setText("");
            packetLogger.revalidate();
            packetLogger.repaint();
        });
        var fileChooser = new JFileChooser();
        fileChooser.addActionListener(actionEvent -> {
            var fileSelected = fileChooser.getSelectedFile();
            try {
                packetLogger.readPacketFile(fileSelected);
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

        this.setJMenuBar(menuToolbar);

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
