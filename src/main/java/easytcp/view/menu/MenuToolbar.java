package easytcp.view.menu;

import easytcp.service.ServiceProvider;
import easytcp.view.menu.help.AboutTCPHelpScreen;
import easytcp.view.menu.help.GeneralHelpScreen;

import javax.swing.*;
import java.awt.event.ActionListener;
import java.io.File;

/* This is the top left corner menu toolbar
 */
public class MenuToolbar {
  private final JMenuBar menuBar;
  private final JMenuItem newMenuItem = new JMenuItem("New");
  private final JMenuItem openMenuItem =  new JMenuItem("Open");
  private final JMenuItem savePcapMenuItem = new JMenuItem("Save capture file");
  private final JMenuItem saveCaptureDiagramMenuItem = new JMenuItem("Save arrows diagram");

  public MenuToolbar() {
    super();
    this.menuBar = new JMenuBar();
    initUI();
  }

    private void initUI () {
      createMenuBar();
    }

  private void createMenuBar () {
    var fileMenu = new JMenu("File");
    var helpMenu = new JMenu("Help");
    var exitMenuItem = new JMenuItem("Exit");
    exitMenuItem.setToolTipText("Exit application");
    exitMenuItem.addActionListener(event -> System.exit(0));

    fileMenu.add(newMenuItem);
    fileMenu.add(openMenuItem);
    fileMenu.add(savePcapMenuItem);
    fileMenu.add(saveCaptureDiagramMenuItem);
    fileMenu.addSeparator();
    fileMenu.add(exitMenuItem);
    var general = new JMenuItem("General");
    addItemListener(general, i -> new GeneralHelpScreen());
    var aboutTcp =  new JMenuItem("About TCP");
    addItemListener(aboutTcp, i -> new AboutTCPHelpScreen());
    helpMenu.add(aboutTcp);
    helpMenu.add(general);
    var savePcapFileChooser = new JFileChooser();
    savePcapFileChooser.addActionListener(s -> {
      var fileSelected = savePcapFileChooser.getSelectedFile();
      ServiceProvider.getInstance().getCaptureSaveService().saveCapture(fileSelected.getPath());
    });

    var saveArrowsDiagramFileChooser = new JFileChooser();
    saveArrowsDiagramFileChooser.addActionListener(i -> {
      var fileSelected = saveArrowsDiagramFileChooser.getSelectedFile();
      ServiceProvider.getInstance().getCaptureSaveService().saveArrowDiagram(fileSelected.getPath());
    });

    addItemListener(saveCaptureDiagramMenuItem, i -> {
      saveArrowsDiagramFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
      var workingDirectory = new File(System.getProperty("user.dir"));
      saveArrowsDiagramFileChooser.setDialogTitle("Save arrows diagram");
      saveArrowsDiagramFileChooser.setCurrentDirectory(workingDirectory);
      saveArrowsDiagramFileChooser.showSaveDialog(menuBar);
      saveArrowsDiagramFileChooser.setMultiSelectionEnabled(false);
      saveArrowsDiagramFileChooser.setVisible(true);
    });

    addItemListener(savePcapMenuItem, i -> {
      savePcapFileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);

      var workingDirectory = new File(System.getProperty("user.dir"));
      savePcapFileChooser.setCurrentDirectory(workingDirectory);
      savePcapFileChooser.setDialogTitle("Save capture file");
      savePcapFileChooser.showSaveDialog(menuBar);
      savePcapFileChooser.setMultiSelectionEnabled(false);
      savePcapFileChooser.setVisible(true);
    });

    menuBar.add(fileMenu);
    menuBar.add(helpMenu);
    menuBar.setVisible(true);

  }

  public void addItemListener(JMenuItem menuItem, ActionListener actionListener) {
    menuItem.addActionListener(actionListener);
  }

  public void addNewMenuItemListener(ActionListener actionListener) {
    newMenuItem.addActionListener(actionListener);
  }

  public void addOpenMenuItemListener(ActionListener actionListener) {
    openMenuItem.addActionListener(actionListener);
  }

  public JMenuBar getMenuBar() {
    return this.menuBar;
  }
}
