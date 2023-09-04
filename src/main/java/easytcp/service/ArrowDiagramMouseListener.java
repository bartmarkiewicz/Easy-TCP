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
    private final ArrowDiagram arrowDiagram;
    private final PacketLog packetLog;

    public TCPConnection getSelectedConnection() {
        return selectedConnection;
    }

    public ArrowDiagramMouseListener(ArrowDiagram arrowDiagram, PacketLog packetLog) {
        this.arrowDiagram = arrowDiagram;
        this.packetLog = packetLog;
    }

    public void setSelectedConnection(TCPConnection selectedConnection) {
        this.selectedConnection = selectedConnection;
    }

    public EasyTCPacket getSelectedPacket() {
        return selectedPacket;
    }

    @Override
    public void mouseClicked(MouseEvent e) {
        if (e.getY() < 60 || selectedConnection == null) {
            //clicked above the arrows diagram, or did not have a connection selected
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
            arrowDiagram.setSelectedPacket(selectedPacket, false);
            packetLog.refreshPacketLog(true);
        }

        LOGGER.debug("Mouse click detected position x %s y %s, packet segment %s"
                .formatted(e.getX(), e.getY(), positionInList));
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
