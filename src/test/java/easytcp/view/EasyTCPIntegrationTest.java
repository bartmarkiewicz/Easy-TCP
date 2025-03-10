package easytcp.view;

import easytcp.Application;
import easytcp.model.application.CaptureData;
import org.assertj.swing.core.GenericTypeMatcher;
import org.assertj.swing.testing.AssertJSwingTestCaseTemplate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.*;
import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.swing.finder.WindowFinder.findFrame;
import static org.assertj.swing.launcher.ApplicationLauncher.application;

//Tests the primary functionality of the application
class EasyTCPIntegrationTest extends AssertJSwingTestCaseTemplate {

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
    void testSaveCapture() throws InterruptedException {
        //tests saving an empty file
        var fileToBeSaved = new File("capture");

        try {
            var frame = findFrame(EasyTCP.class).withTimeout(5500).using(robot());

            frame.menuItemWithPath("File", "Save capture file").click();
            var saveDialog = frame.fileChooser(new GenericTypeMatcher<>(JFileChooser.class) {
                @Override
                protected boolean isMatching(JFileChooser component) {
                    return component.getDialogType() == JFileChooser.SAVE_DIALOG;
                }
            }).requireVisible();

            assertThat(fileToBeSaved.exists()).isFalse();
            saveDialog.fileNameTextBox().setText("capture");
            saveDialog.approve();
            Thread.sleep(1500);
            assertThat(fileToBeSaved.exists()).isTrue();
        } finally {
            fileToBeSaved.deleteOnExit();
        }
    }

    @Test
    void testReadPcapFileAndUseFilters_andSaveDiagram() throws InterruptedException {
        //tests reading a pcap file, filtering and then saving a diagram
        var frame = findFrame(EasyTCP.class).withTimeout(4000).using(robot());
        //opens a prepared capture file
        frame.menuItemWithPath("File", "Open").click();
        var openFileDialog = frame.fileChooser(new GenericTypeMatcher<>(JFileChooser.class) {
            @Override
            protected boolean isMatching(JFileChooser component) {
                return component.getDialogType() == JFileChooser.OPEN_DIALOG;
            }
        }).requireVisible();
        openFileDialog.selectFile(new File("src/test/resources/testPcapFile"));
        openFileDialog.approveButton().click();

        Thread.sleep(6000); // wait for the file to load

        //asserting file has been successfully read
        frame.label("connection count")
                .requireText("%s TCP connections\n".formatted(CaptureData.getInstance().getTcpConnectionMap().keySet().size()));
        frame.label("packets count")
                .requireText("%s packets captured".formatted(CaptureData.getInstance().getPackets().getPackets().size()));
        frame.textBox("connectionsInformation")
                .requireText("""
                             TCP connections
                             32 status ESTABLISHED
                             1 status FIN_WAIT_2
                             7 status CLOSED
                             """
                );
        //selects a connection in the connection selector
        var connectionSelect = frame.comboBox("connectionSelector");
        connectionSelect.selectItem(0);
        //refilters the packets
        frame.button("filter").click();
        Thread.sleep(500);
        frame.label("connection count")
                .requireText("1 TCP connections\n");
        frame.label("packets count") //asserts correct connection
                .requireText("53 packets captured");

        //then save arrows diagram
        frame.menuItemWithPath("File", "Save arrows diagram").click();

        var saveDialog = frame.fileChooser(new GenericTypeMatcher<>(JFileChooser.class) {
            @Override
            protected boolean isMatching(JFileChooser component) {
                return component.getDialogType() == JFileChooser.SAVE_DIALOG;
            }
        }).requireVisible();
        Thread.sleep(500);

        //asserts the file is created by easy TCP after saving the dialog
        var fileToBeSaved = new File("abc.png");
        try {
            assertThat(fileToBeSaved.exists()).isFalse();
            saveDialog.fileNameTextBox().setText("abc");
            Thread.sleep(1000);
            saveDialog.approve();
            Thread.sleep(1500);
            assertThat(fileToBeSaved.exists()).isTrue();
        } finally {
            fileToBeSaved.deleteOnExit();
        }
    }
}