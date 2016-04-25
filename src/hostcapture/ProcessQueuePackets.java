/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hostcapture;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
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
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author parres
 */
public class ProcessQueuePackets implements Runnable {

    private final LinkedBlockingQueue<PacketQueueElement> queue;
    private FlowMap flows = new FlowMap();
    private int fileCounter;
    private String filename;
    private double packetCounter;
    private double flowCounter;

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
        this.fileCounter = 1;
        this.packetCounter = 0;
        this.flowCounter = 0;

        String date = new SimpleDateFormat("yyyyMMdd").format(new Date());
        this.filename = String.format("%s\\%s-%s-%s", Config.getConfig("FilePath"), Config.getConfig("FileBaseName"), Config.getConfig("user"), date);

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
        
        boolean inPacket = true;
        try {
            byte[] devMac = element.getDev().getHardwareAddress();
            byte[] srcMac = eth.source();
            
            inPacket = (Arrays.equals(devMac, srcMac)) ? false : true;
        } catch (IOException ex) {
            Logger.getLogger(ProcessQueuePackets.class.getName()).log(Level.SEVERE, null, ex);
        }
       
        int flowID = p.getFlowKey().hashCode();
        long ts = p.getCaptureHeader().timestampInMillis();
        int bytes = p.getCaptureHeader().caplen();

        String mac = null;
        try {
            mac = FormatUtils.mac(element.getDev().getHardwareAddress());
        } catch (IOException ex) {
            Logger.getLogger(ProcessQueuePackets.class.getName()).log(Level.SEVERE, null, ex);
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

        String farIP;
        String localIP;
        
        if(inPacket) {
            //El paquete es entrante
            farIP = s_ip;
            localIP = d_ip;
        } else {
            //El paquete es saliente
            farIP = d_ip;
            localIP = s_ip;
        }

        Tcp tcp = new Tcp();
        Udp udp = new Udp();

        String protocol;
        int port;

        if (p.hasHeader(tcp)) {
            protocol = "TCP";
            if (inPacket) {
                port = tcp.source();
            } else {
                port = tcp.destination();
            }
        } else if (p.hasHeader(udp)) {
            protocol = "UDP";
            if (inPacket) {
                port = udp.source();
            } else {
                port = udp.destination();
            }
        } else {
            return;
        }
        
        if(farIP.isEmpty()) {
            System.out.println(p.toString());
        }
        
        /* Start testing for HTTP and get URL */
        String http_host = null;
        String http_method = null;
        String http_url = null;
        String http_useragent = null;
        String http_contenttype = null;
        String http_response = null;
        Http http = new Http();
        if(p.hasHeader(http)) {
            if(http.isResponse()==false) {
                http_host = http.fieldValue(Http.Request.Host);
                http_method = http.fieldValue(Http.Request.RequestMethod);
                http_url = http.fieldValue(Http.Request.RequestUrl);
                http_useragent = http.fieldValue(Http.Request.User_Agent);
            } else {
                http_contenttype = http.fieldValue(Http.Response.Content_Type);
                http_response = http.fieldValue(Http.Response.ResponseCode)+" "+http.fieldValue(Http.Response.ResponseCodeMsg);
            }
        }
        
        Flow flow = new Flow(flowID, farIP, protocol, port, ts, ts, element.getDev().getName(), mac, 1, bytes,http_host,http_method,http_url,http_useragent,http_contenttype,http_response);
        flows.add(flow);

        HostCapture.getFrame().getInterfacesTable().getModel().setValueAt(localIP, element.getDevice_index(), 1);
        HostCapture.getFrame().getInterfacesTable().getModel().setValueAt(this.packetCounter++, element.getDevice_index(), 2);
        HostCapture.getFrame().getInterfacesTable().getModel().setValueAt(flows.count()+this.flowCounter, element.getDevice_index(), 3);
        

        if (flows.count() >= Double.valueOf(Config.getConfig("CountFlowsWriteToFile"))) {
            FlowMap copyFlows;
            copyFlows = flows;
            this.flowCounter += flows.count();
            flows = new FlowMap();

            try {
                writeToFile(copyFlows);
            } catch (IOException ex) {
                Logger.getLogger(ProcessQueuePackets.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private void writeToFile(FlowMap flowmap) throws IOException {

        String filename;
        File file;
        FileWriter writer;

        filename = String.format("%s-%03d.csv", this.filename, this.fileCounter);
        file = new File(filename);
        if (file.exists()) {
            //El archivo si existe
            double kbytes = file.length() / 1024;
            if (kbytes >= Double.valueOf(Config.getConfig("FileMaxSize"))) {
                // El archivo mide más del tamaño maximo.
                this.fileCounter++;
                filename = String.format("%s-%03d.csv", this.filename, this.fileCounter);
                file = new File(filename);
            } else {
                // El archivo mide menos del tamaño maximo.
            }
        } else {
            // el archivo no existe.
            file.createNewFile();
        }

        writer = new FileWriter(file,true);
        writer.append(flowmap.toSCV());
        writer.flush();
        writer.close();

    }
}
