package easytcp.view;

import javax.swing.*;
import java.awt.event.ActionListener;

public class MenuToolbar {
  private final JMenuBar menuBar;
  private final JMenuItem newMenuItem = new JMenuItem("New");;
  private final JMenuItem openMenuItem =  new JMenuItem("Open");
  private final JMenuItem saveMenuItem = new JMenuItem("Save");

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

      var exitMenuItem = new JMenuItem("Exit");
      exitMenuItem.setToolTipText("Exit application");
      exitMenuItem.addActionListener((event) -> System.exit(0));

      fileMenu.add(newMenuItem);
      fileMenu.add(openMenuItem);
      fileMenu.add(saveMenuItem);
      fileMenu.addSeparator();
      fileMenu.add(exitMenuItem);

      menuBar.add(fileMenu);
      menuBar.setVisible(true);

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
