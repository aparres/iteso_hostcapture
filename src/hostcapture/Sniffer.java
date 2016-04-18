package hostcapture;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 *
 * @author parres
 */
public class Sniffer implements Runnable {
    PcapIf device;
    String device_name;
    Pcap pcap;
    LinkedBlockingQueue<PacketQueueElement> pkt_queue;

    @Override
    public void run() {
        this.startSniffer();
    }
    
    private class SnifferShutDownHook implements Runnable {

        private final Pcap pcap;
        
        public SnifferShutDownHook(Pcap _pcap) {
            pcap = _pcap;
        }
        @Override
        public void run() {
            if(pcap != null) {
                pcap.breakloop();
                pcap.close();
                System.out.println("PCAP LOOP Ended");
            }
        }
    }
    
    public Sniffer(PcapIf _device, LinkedBlockingQueue<PacketQueueElement> _pkt_queue) {
        device = _device;
        device_name = device.getName();
        pkt_queue = _pkt_queue;
    }
    
    public Sniffer(String _device_name, LinkedBlockingQueue<PacketQueueElement> _pkt_queue) {

        for(PcapIf dev : Sniffer.getInterfacesName()) {
            if(dev.getName().equals(_device_name)) {
                device = dev;
            }
        }
        
        device_name = _device_name;
        pkt_queue = _pkt_queue;
    }

    public void startSniffer() {
        int snaplen = 64 * 1024;           // Capture all packets, no truncation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        StringBuilder errbuf = new StringBuilder();
        packetHandler handler = new packetHandler(device);

        pcap = Pcap.openLive(device_name, snaplen, flags, timeout, errbuf);
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }  

        Runtime.getRuntime().addShutdownHook(new Thread(new SnifferShutDownHook(pcap)));
        pcap.loop(Pcap.LOOP_INFINITE, handler, pkt_queue); 
    }
    
    public static List<PcapIf> getInterfacesName() {
        List<PcapIf> alldevs = new ArrayList<>(); 
        StringBuilder errbuf = new StringBuilder();     // For any error msgs  
        int r;
        
        r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.OK && !alldevs.isEmpty()) {
        } else {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return null;
        }
        
        return alldevs;
    }
    
}
