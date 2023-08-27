package easytcp.view.menu;

import easytcp.service.ServiceProvider;
import easytcp.view.menu.help.AboutTCPHelpScreen;
import easytcp.view.menu.help.GeneralHelpScreen;

import javax.swing.*;
import java.awt.event.ActionListener;

public class MenuToolbar {
  private final JMenuBar menuBar;
  private final JMenuItem newMenuItem = new JMenuItem("New");;
  private final JMenuItem openMenuItem =  new JMenuItem("Open");
  private final JMenuItem saveMenuItem = new JMenuItem("Save capture file");

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
      exitMenuItem.addActionListener((event) -> System.exit(0));

      fileMenu.add(newMenuItem);
      fileMenu.add(openMenuItem);
      fileMenu.add(saveMenuItem);
      fileMenu.addSeparator();
      fileMenu.add(exitMenuItem);
      var general = new JMenuItem("General");;
      addItemListener(general, i -> {
        new GeneralHelpScreen();
      });
      var aboutTcp =  new JMenuItem("About Tcp");
      addItemListener(aboutTcp, i -> {
        new AboutTCPHelpScreen();
      });
      helpMenu.add(aboutTcp);
      helpMenu.add(general);
      var fileChooser = new JFileChooser();
      fileChooser.addActionListener(s -> {
        var fileSelected = fileChooser.getSelectedFile();
        ServiceProvider.getInstance().getCaptureSaveService().saveCapture(fileSelected.getPath());
      });

      addItemListener(saveMenuItem, i -> {
        fileChooser.setFileSelectionMode(JFileChooser.SAVE_DIALOG);
        fileChooser.showSaveDialog(menuBar);
        fileChooser.setMultiSelectionEnabled(false);
        fileChooser.setVisible(true);
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

  public void addSaveMenuItemListener(ActionListener actionListener) {
    saveMenuItem.addActionListener(actionListener);
  }

  public JMenuBar getMenuBar() {
    return this.menuBar;
  }
}
