/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hostcapture;

import java.util.concurrent.LinkedBlockingQueue;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 *
 * @author parres
 */
public class packetHandler implements PcapPacketHandler<LinkedBlockingQueue<PacketQueueElement>> {

    PcapIf device;
    int index;
    
    @Override
    public void nextPacket(PcapPacket jp, LinkedBlockingQueue<PacketQueueElement> pk_queue) {
        PcapPacket p = new PcapPacket(jp);
        pk_queue.offer(new PacketQueueElement(device,p,index));
    }

    public packetHandler(PcapIf _device, int _index) {
        device = _device;
        index = _index;
    }
}  