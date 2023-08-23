package easytcp.view.menu.help;

import javax.swing.*;
import java.awt.*;

public class GeneralHelpScreen {

  public GeneralHelpScreen() {
    var newFrame = new JFrame("EasyTCP General Help");
    var screenSize = Toolkit.getDefaultToolkit().getScreenSize();
    screenSize.setSize(screenSize.width - 120, screenSize.height - 120);
    newFrame.setPreferredSize(screenSize);

    newFrame.setVisible(true);
  }
}
