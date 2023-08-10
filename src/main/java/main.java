import view.EasyTCP;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;

public class main {

    public static void main(String[] args) throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(() -> {
            EasyTCP application = new EasyTCP();
            application.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            application.pack();
          });
    }
}
