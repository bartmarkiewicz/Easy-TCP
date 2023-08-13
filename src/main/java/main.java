import view.EasyTCP;

import javax.swing.*;

public class main {

    public static void main(String[] args){
        SwingUtilities.invokeLater(() -> {
            EasyTCP application = new EasyTCP();
            application.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            application.pack();
        });
    }
}
