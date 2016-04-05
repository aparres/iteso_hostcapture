/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hostcapture;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.lan.Ethernet.EthernetType;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Http.Request;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author parres
 */
public class ProcessQueuePackets implements Runnable {

    private final LinkedBlockingQueue<PacketQueueElement> queue;

    private class ProcessPacketShutDownHook implements Runnable {

        private final LinkedBlockingQueue<PacketQueueElement> queue;

        public ProcessPacketShutDownHook(LinkedBlockingQueue<PacketQueueElement> _queue) {
            queue = _queue;
        }

        @Override
        public void run() {
            System.out.printf("Processing %d packets before end\n", queue.size());
            while (!queue.isEmpty()) {
                processPacket(queue.poll());
            }
            System.out.println("QUEUE PROCESS FINISH");
        }
    }

    public ProcessQueuePackets(LinkedBlockingQueue<PacketQueueElement> _queue) {
        this.queue = _queue;
        Runtime.getRuntime().addShutdownHook(new Thread(new ProcessPacketShutDownHook(queue)));
    }

    @Override
    public void run() {
        while (true) {
            PacketQueueElement p;
            try {
                p = queue.take();
                processPacket(p);
            } catch (InterruptedException ex) {
                Logger.getLogger(ProcessQueuePackets.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private void processPacket(PacketQueueElement element) {
        String line = new String();
        PcapPacket p = element.getPacket();
       
        if (!p.hasHeader(Ethernet.ID)) {
            //Not Ethernet Frame 
            return;
        }

        Ethernet eth = new Ethernet();
        p.hasHeader(eth);

        line += String.format("%s\t", element.getDev().getDescription());

            //Frame Number 
        long frame_number = p.getFrameNumber();
        line += String.format("%d\t", frame_number);
                
        line += String.format("0x%x\t", p.getFlowKey().hashCode());

        long p_time = p.getCaptureHeader().timestampInMillis();
        line += String.format("%d\t", p_time);

        line += String.format("%d\t", p.getCaptureHeader().caplen());

        if (eth.type() != EthernetType.IP4.getId() && eth.type() != EthernetType.IP6.getId()) {
            // Not IP Traffic
            return;
        }

        if (eth.type() == EthernetType.IP4.getId()) {
            Ip4 ip_head = new Ip4();
            p.hasHeader(ip_head);
            line += String.format("%s\t%s\t",
                    FormatUtils.ip(ip_head.source()), FormatUtils.ip(ip_head.destination()));
        }

        if (eth.type() == EthernetType.IP6.getId()) {
            Ip6 ip_head = new Ip6();
            p.hasHeader(ip_head);
            line += String.format("%s\t%s\t",
                    FormatUtils.ip(ip_head.source()), FormatUtils.ip(ip_head.destination()));
        }

        Tcp tcp = new Tcp();
        Udp udp = new Udp();

        if (p.hasHeader(tcp)) {
            line += String.format("TCP\t%d\t%d\t", tcp.source(), tcp.destination());
            Http http = new Http();
            if (p.hasHeader(http)) {
                if (!http.isResponse()) {
                    if (http.fieldValue(Request.Referer) != null) {
                        line += String.format("HTTP\t%s http://%s%s\t REFER %s\t", http.fieldValue(Request.RequestMethod),
                                http.fieldValue(Request.Host), http.fieldValue(Request.RequestUrl), http.fieldValue(Request.Referer));
                    } else {
                        line += String.format("HTTP\t%s http://%s%s\t", http.fieldValue(Request.RequestMethod),
                                http.fieldValue(Request.Host), http.fieldValue(Request.RequestUrl));
                    }
                }
            }
        } else if (p.hasHeader(udp)) {
            line += String.format("UDP\t%d\t%d\t", udp.source(), udp.destination());
        } else {
            //NO TCP/UDP
            return;
        }
        System.out.printf("%s\n", line);
    }
}
