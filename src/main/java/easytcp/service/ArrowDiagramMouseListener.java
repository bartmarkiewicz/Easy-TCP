package easytcp.service;

import easytcp.model.packet.EasyTCPacket;
import easytcp.model.packet.TCPConnection;
import easytcp.view.ArrowDiagram;
import easytcp.view.PacketLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

public class ArrowDiagramMouseListener implements MouseListener {
    private static final Logger LOGGER = LoggerFactory.getLogger(ArrowDiagramMouseListener.class);
    private TCPConnection selectedConnection;
    private EasyTCPacket selectedPacket;

    public TCPConnection getSelectedConnection() {
        return selectedConnection;
    }

    public void setSelectedConnection(TCPConnection selectedConnection) {
        this.selectedConnection = selectedConnection;
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        //use getX and getY

        LOGGER.debug("Mouse click detected position -x %s y- %s".formatted(e.getX(), e.getY()));
        if (e.getY() < 60 || selectedConnection == null) {
            //clicked above the arrow diagram, or did not have a connection selected
            return;
        }

        //Each packet height on the arrow diagram is 140px
        var positionInList = (int) Math.ceil(e.getY()/140f) - 1;
        if (selectedConnection.getPacketContainer().getPackets().size() > positionInList) {
            if (this.selectedPacket != null) {
                this.selectedPacket.setSelectedPacket(false);
            }
            this.selectedPacket = selectedConnection.getPacketContainer().getPackets().get(positionInList);
            this.selectedPacket.setSelectedPacket(true);
            ArrowDiagram.getInstance().setSelectedPacket(selectedPacket, false);
            PacketLog.getPacketLog().refreshPacketLog(true);
        }

        LOGGER.debug("Mouse click detected position on screen -x %s y- %s, packet segment %s"
                .formatted(e.getXOnScreen(), e.getYOnScreen(), positionInList));

    }

    @Override
    public void mousePressed(MouseEvent e) {
    }

    @Override
    public void mouseReleased(MouseEvent e) {
    }

    @Override
    public void mouseEntered(MouseEvent e) {
    }

    @Override
    public void mouseExited(MouseEvent e) {
    }
}
