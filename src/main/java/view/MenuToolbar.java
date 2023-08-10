package view;

import javax.swing.*;
import java.awt.event.ActionListener;

public class MenuToolbar extends JMenuBar {

  private final JMenuItem newMenuItem = new JMenuItem("New");;
  private final JMenuItem openMenuItem =  new JMenuItem("Open");
  private final JMenuItem saveMenuItem = new JMenuItem("Save");

  public MenuToolbar() {
    super();
    initUI();
  }

    private void initUI () {
      createMenuBar();
    }

    private void createMenuBar () {
      var fileMenu = new JMenu("File");
      var impMenu = new JMenu("Import");

      var newsMenuItem = new JMenuItem("Import newsfeed list...");
      var bookmarksMenuItem = new JMenuItem("Import bookmarks...");
      var importMailMenuItem = new JMenuItem("Import mail...");

      impMenu.add(newsMenuItem);
      impMenu.add(bookmarksMenuItem);
      impMenu.add(importMailMenuItem);

      var exitMenuItem = new JMenuItem("Exit");
      exitMenuItem.setToolTipText("Exit application");
      exitMenuItem.addActionListener((event) -> System.exit(0));

      fileMenu.add(newMenuItem);
      fileMenu.add(openMenuItem);
      fileMenu.add(saveMenuItem);
      fileMenu.addSeparator();
      fileMenu.add(exitMenuItem);

      this.add(fileMenu);
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
}
