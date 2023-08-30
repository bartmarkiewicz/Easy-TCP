package easytcp.service;

import easytcp.model.application.ApplicationStatus;

import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;

public class ResizeListener implements ComponentListener {

    public void componentHidden(ComponentEvent e) {}
    public void componentMoved(ComponentEvent e) {}
    public void componentShown(ComponentEvent e) {}

    public void componentResized(ComponentEvent e) {
        var newSize = e.getComponent().getBounds().getSize();
        ApplicationStatus.getStatus().setFrameDimension(newSize);
    }
}
