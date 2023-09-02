package easytcp;

import easytcp.configuration.LogConfiguration;
import easytcp.view.EasyTCP;

import javax.swing.*;

public class Application {
    /*Application entry point
     */
    public static void main(String[] args){
        LogConfiguration.configureLog4j();
        //Creates the application on the Swing UI thread.
        SwingUtilities.invokeLater(() -> {
            EasyTCP application = new EasyTCP();
            application.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            application.pack();
        });
    }
}
