package hostcapture;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;

/**
 *
 * @author parres
 */
public class Sniffer implements Runnable {
    PcapIf device;
    String device_name;
    int device_index;
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
                System.out.println("\tPCAP LOOP Ended");
            }
        }
    }
    
            
    public Sniffer(PcapIf _device, LinkedBlockingQueue<PacketQueueElement> _pkt_queue, int index) {
        device = _device;
        device_name = device.getName();
        pkt_queue = _pkt_queue;
        device_index = index;
    }

    public Sniffer(String _device_name, LinkedBlockingQueue<PacketQueueElement> _pkt_queue, int index) {
        this((PcapIf)null,_pkt_queue, index);
        
        device = getDeviceFromName(_device_name);
    }
    
    public void startSniffer() {
        int snaplen = 64 * 1024;           // Capture all packets, no truncation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        StringBuilder errbuf = new StringBuilder();
        packetHandler handler = new packetHandler(device,device_index);

        pcap = Pcap.openLive(device_name, snaplen, flags, timeout, errbuf);
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }  

        Runtime.getRuntime().addShutdownHook(new Thread(new SnifferShutDownHook(pcap)));
        pcap.loop(Pcap.LOOP_INFINITE, handler, pkt_queue); 
    }
    
    public static List<PcapIf> getInterfaces() {
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
    
    public static PcapIf getDeviceFromName(String deviceName) {
        PcapIf device = null;
        
        for(PcapIf dev : Sniffer.getInterfaces()) {
            if(dev.getName().equals(deviceName)) {
                device = dev;
            }
        }
        
        return device;
    }
    
    public static List<PcapAddr> getIPAddressFromDeviceName(String deviceName) {
       PcapIf device = getDeviceFromName(deviceName);
       return device.getAddresses();
    }

    
}
   