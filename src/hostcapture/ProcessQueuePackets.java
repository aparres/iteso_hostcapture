/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hostcapture;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.PcapAddr;
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
    private FlowMap flows = new FlowMap();

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
        
        PcapPacket p = element.getPacket();
        
        
        if (!p.hasHeader(Ethernet.ID)) {
            //Not Ethernet Frame 
            return;
        }

        Ethernet eth = new Ethernet();
        p.hasHeader(eth);
        if (eth.type() != EthernetType.IP4.getId() && eth.type() != EthernetType.IP6.getId()) {
            // Not IP Traffic
            return;
        }
        
        int  flowID = p.getFlowKey().hashCode();
        long ts = p.getCaptureHeader().timestampInMillis();
        int bytes = p.getCaptureHeader().caplen();
        
        String mac = null;
        try {
            mac = FormatUtils.mac(element.getDev().getHardwareAddress());
        } catch (IOException ex) {
            Logger.getLogger(ProcessQueuePackets.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        ArrayList<String> local_ips = new ArrayList();
        for(PcapAddr ip : element.getDev().getAddresses()) {
            local_ips.add(FormatUtils.ip(ip.getAddr().getData()));
        }
 
        String s_ip = "";
        String d_ip = "";
        if (eth.type() == EthernetType.IP4.getId()) {
            Ip4 ip_head = new Ip4();
            p.hasHeader(ip_head);
            s_ip = FormatUtils.ip(ip_head.source());
            d_ip = FormatUtils.ip(ip_head.destination());
        } else if (eth.type() == EthernetType.IP6.getId()) {
            Ip6 ip_head = new Ip6();
            p.hasHeader(ip_head);
            s_ip = FormatUtils.ip(ip_head.source());
            d_ip = FormatUtils.ip(ip_head.destination());
        }

        String farIP = "";
        boolean farIPatDst = true;
        for(String ip : local_ips) {
            if(s_ip.compareTo(ip)==0) {
                farIP = d_ip;
                break;
            }
            
            if(d_ip.compareTo(ip)==0) {
                farIP = s_ip;
                farIPatDst = false;
                break;
            }
        }
        
        Tcp tcp = new Tcp();
        Udp udp = new Udp();
        
        String protocol = "";
        int port = 0;

        if (p.hasHeader(tcp)) {
            protocol = "TCP";
            if(farIPatDst) {
                port = tcp.destination();
            } else {
                port = tcp.source();
            }
        } else if (p.hasHeader(udp)) {
            protocol = "UDP";
            if(farIPatDst) {
                port = udp.destination();
            } else {
                port = udp.source();
            }
        } else {
            return;
        }
        
        Flow flow = new Flow(flowID,farIP,protocol,port,ts,ts,element.getDev().getName(),mac,1,bytes);
        flows.add(flow);
        
        System.out.println(flows.toString());
    }
}
