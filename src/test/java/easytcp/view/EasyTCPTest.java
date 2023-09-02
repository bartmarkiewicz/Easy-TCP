package easytcp.view;

import easytcp.Application;
import org.assertj.swing.core.GenericTypeMatcher;
import org.assertj.swing.testing.AssertJSwingTestCaseTemplate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;

import java.io.File;

import static org.assertj.swing.finder.WindowFinder.findFrame;
import static org.assertj.swing.launcher.ApplicationLauncher.application;

class EasyTCPTest extends AssertJSwingTestCaseTemplate {

    @BeforeEach
    public void onSetUp() {
        setUpRobot();
        application(Application.class).start();
    }

    @AfterEach
    void tearDown() {
        cleanUp();
    }

    @Test
    void testSaveArrowsDiagram() {
        var frame = findFrame(EasyTCP.class).withTimeout(5500).using(robot());

        frame.menuItemWithPath("File", "Save arrows diagram").click();
        var saveDialog = frame.fileChooser(new GenericTypeMatcher<>(JFileChooser.class) {
            @Override
            protected boolean isMatching(JFileChooser component) {
                return component.getDialogType() == JFileChooser.SAVE_DIALOG;
            }
        }).requireVisible();
        saveDialog.approve();
        saveDialog.requireNotVisible();
        frame.requireFocused();
    }

    @Test
    void testSaveCapture() {
        var frame = findFrame(EasyTCP.class).withTimeout(5500).using(robot());

        frame.menuItemWithPath("File", "Save capture file").click();
        var saveDialog = frame.fileChooser(new GenericTypeMatcher<>(JFileChooser.class) {
            @Override
            protected boolean isMatching(JFileChooser component) {
                return component.getDialogType() == JFileChooser.SAVE_DIALOG;
            }
        }).requireVisible();
        saveDialog.approve();
    }

    @Test
    void testReadPcapFileAndUseFilters() {
        var frame = findFrame(EasyTCP.class).withTimeout(5500).using(robot());

        frame.menuItemWithPath("File", "Open").click();
        var openFileDialog = frame.fileChooser(new GenericTypeMatcher<>(JFileChooser.class) {
            @Override
            protected boolean isMatching(JFileChooser component) {
                return component.getDialogType() == JFileChooser.OPEN_DIALOG;
            }
        }).requireVisible();
        openFileDialog.selectFile(new File("Easy-TCP/src/test/resources/testPcapFile"));
        openFileDialog.approveButton().click();

    }
}