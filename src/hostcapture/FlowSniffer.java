/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hostcapture;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author parres
 */
public class FlowSniffer {

    String device;
    Pcap pcap;

    private class FlowSnifferShutDownHook implements Runnable {

        private final Pcap pcap;

        public FlowSnifferShutDownHook(Pcap _pcap) {
            pcap = _pcap;
        }

        @Override
        public void run() {
            if (pcap != null) {
                pcap.breakloop();
                pcap.close();
                System.out.println("PCAP LOOP Ended");
            }
        }
    }

    private class PrintMapThread implements Runnable {
        
        JFlowMap map;
        
        public PrintMapThread(JFlowMap _map) {
            map = _map;
        }
        
        @Override
        public void run() {
            while(true) {
                if(map != null) {
                    String line = new String();
                    
                    System.out.println("**********************");
                    line += String.format("Total Flows %d - Total Pkt %d\n",
                            map.getTotalPacketCount(),
                            map.size());
                    
                    for(JFlow flow : map.values()) {
                        line += "\t--";
                        for(JPacket p : flow.getAll()) {
                            line += String.format("%d,",p.getFrameNumber());
                        }
                        line += "\n";
                    }
                    System.out.println(line);
                    System.out.println(map.toString());

                    try {
                        Thread.sleep(30000);
                    } catch (InterruptedException ex) {
                        Logger.getLogger(FlowSniffer.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        }
        
    }
    public FlowSniffer(String _device) {

        int snaplen = 64 * 1024;           // Capture all packets, no truncation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        StringBuilder errbuf = new StringBuilder();
        JFlowMap map = new JFlowMap(); 
        
        device = _device;
        pcap = Pcap.openLive(device, snaplen, flags, timeout, errbuf);
        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }
        
        Thread t = new Thread(new PrintMapThread(map));
        t.start();
        
        pcap.loop(Pcap.LOOP_INFINITE, map, null);
        System.out.println(map.toString());  
    }

}