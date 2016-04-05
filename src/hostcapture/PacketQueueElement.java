/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hostcapture;

import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author parres
 */
public class PacketQueueElement {
    private PcapIf dev;
    private PcapPacket packet;

    public PacketQueueElement(PcapIf _dev, PcapPacket _packet) {
        this.dev = _dev;
        this.packet = _packet;
    }
    
    public PcapIf getDev() {
        return dev;
    }

    public void setDev(PcapIf dev) {
        this.dev = dev;
    }
    public PcapPacket getPacket() {
        return packet;
    }

    public void setPacket(PcapPacket packet) {
        this.packet = packet;
    }
    
}
