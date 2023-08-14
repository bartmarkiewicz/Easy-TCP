package easytcp;

import easytcp.configuration.LogConfiguration;
import easytcp.view.EasyTCP;

import javax.swing.*;

public class main {

    public static void main(String[] args){
        LogConfiguration.configureLog4j();
        SwingUtilities.invokeLater(() -> {
            EasyTCP application = new EasyTCP();
            application.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            application.pack();
        });
    }
}
