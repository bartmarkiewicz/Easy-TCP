package easytcp.view;

import easytcp.model.application.ApplicationStatus;
import easytcp.model.application.FiltersForm;
import easytcp.service.ResizeListener;
import easytcp.service.ServiceProvider;
import easytcp.view.menu.MenuToolbar;
import easytcp.view.options.OptionsPanel;
import mdlaf.MaterialLookAndFeel;
import mdlaf.themes.MaterialLiteTheme;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/* This represents the main window of the application
 */
public class EasyTCP extends JFrame {
    public EasyTCP() {
        super();
        this.setTitle("Easy TCP");
        Dimension screenSize = Toolkit.getDefaultToolkit().getScreenSize();
        ApplicationStatus.getStatus().setFrameDimension(new Dimension(screenSize.width - 120, screenSize.height - 120));
        screenSize.setSize(screenSize.width - 120, screenSize.height - 120);
        this.setPreferredSize(screenSize);
        try {
            //sets a material look and feel
            UIManager.setLookAndFeel(new MaterialLookAndFeel(new MaterialLiteTheme()));
        } catch (Exception e) {
            System.out.println("Error setting material styling, defaulting to swing styling.");
        }
        addResizeHandler();
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
        arrowDiagram.repaint();
        arrowDiagram.revalidate();
        var filtersForm = FiltersForm.getInstance();
        var packetLogger = new PacketLog(filtersForm, ServiceProvider.getInstance());

        var optionsPanel = new OptionsPanel(filtersForm, packetLogger);
        firstRow.add(optionsPanel.getPanel());

        this.getContentPane().add(firstRow);

        var packetViewScroll = new JScrollPane(packetLogger.getPacketTextPane());
        packetLogger.setScrollPane(packetViewScroll);
        packetViewScroll.setVerticalScrollBarPolicy(JScrollPane. VERTICAL_SCROLLBAR_AS_NEEDED);

        var menuToolbar = new MenuToolbar();
        menuToolbar.addNewMenuItemListener((actionEvent) -> packetLogger.newLog());
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
            fileChooser.setDialogType(JFileChooser.OPEN_DIALOG);
            fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
            //make sure the default location in the file chooser is where the app was started.
            var workingDirectory = new File(System.getProperty("user.dir"));
            fileChooser.setCurrentDirectory(workingDirectory);
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

    private void addResizeHandler() {
        addComponentListener(new ResizeListener());
    }
}
