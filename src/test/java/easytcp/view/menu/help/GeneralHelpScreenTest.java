package easytcp.view.menu.help;

import easytcp.Application;
import easytcp.view.EasyTCP;
import org.assertj.swing.core.GenericTypeMatcher;
import org.assertj.swing.testing.AssertJSwingTestCaseTemplate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;

import static org.assertj.swing.finder.WindowFinder.findFrame;
import static org.assertj.swing.launcher.ApplicationLauncher.application;


class GeneralHelpScreenTest extends AssertJSwingTestCaseTemplate {

    @BeforeEach
    public void onSetUp() {
        setUpRobot();
        application(Application.class).start();
    }

    @Test
    void testOpenHelpScreen() {
        var frame = findFrame(EasyTCP.class).withTimeout(5500).using(robot());

        frame.menuItemWithPath("Help", "General").click();
        var generalHelpFrame = findFrame(new GenericTypeMatcher<>(JFrame.class) {
            @Override
            protected boolean isMatching(JFrame component) {
                return "Easy TCP General Help".equals(component.getTitle()) && component.isShowing();
            }
        }).withTimeout(5000).using(robot());

        generalHelpFrame.requireVisible();
        var closeBt = generalHelpFrame.button(new GenericTypeMatcher<>(JButton.class) {
            @Override
            protected boolean isMatching(JButton component) {
                return component.getText().equals("Close");
            }
        }).requireVisible();

        generalHelpFrame.label("header").requireText("Easy TCP user guide");
        closeBt.click();
        generalHelpFrame.requireNotVisible(); //asserting frame is closed
        cleanUp();
    }
}