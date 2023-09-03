package easytcp.view.menu.help;

import easytcp.Application;
import easytcp.view.EasyTCP;
import org.assertj.swing.core.GenericTypeMatcher;
import org.assertj.swing.testing.AssertJSwingTestCaseTemplate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;

import static org.assertj.swing.finder.WindowFinder.findFrame;
import static org.assertj.swing.launcher.ApplicationLauncher.application;

class AboutTCPHelpScreenIntegrationTest extends AssertJSwingTestCaseTemplate {

    @BeforeEach
    public void onSetUp() {
        //starts up the application and sets up a robot (to do the clicking through the screens)
        setUpRobot();
        application(Application.class).start();
    }

    @AfterEach
    void tearDown() {
        cleanUp();
    }

    @Test
    void testOpenHelpScreen() {
        //finds the application window
        var frame = findFrame(EasyTCP.class).withTimeout(4000).using(robot());

        //clicks Help -> About TCP
        frame.menuItemWithPath("Help", "About TCP").click();
        var aboutTcpFrame = findFrame(new GenericTypeMatcher<>(JFrame.class) {
            @Override
            protected boolean isMatching(JFrame component) {
                return "EasyTCP About TCP".equals(component.getTitle()) && component.isShowing();
            }
        }).withTimeout(4000).using(robot());

       aboutTcpFrame.requireVisible();
       var closeBt = aboutTcpFrame.button(new GenericTypeMatcher<>(JButton.class) {
           @Override
           protected boolean isMatching(JButton component) {
               return component.getText().equals("Close");
           }
       }).requireVisible();

       aboutTcpFrame.label("header").requireText("Transmission Control Protocol - TCP");
       closeBt.click();
       aboutTcpFrame.requireNotVisible(); //asserting frame is closed
    }
}