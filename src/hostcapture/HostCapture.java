package hostcapture;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.table.DefaultTableModel;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.format.FormatUtils;

/**
 *
 * @author parres
 */
public class HostCapture {

    ArrayList<Thread> sniffer_threads_list;
    LinkedBlockingQueue<PacketQueueElement> pkt_queue;
    Properties config;
    static AppFrame appFrame;
    Thread  processQueuePacketThread;
    
    private class HostCaptureShutDownHook implements Runnable {

        private final ArrayList<Thread> snifferThs;
        private final Thread processQueueTh;

        public HostCaptureShutDownHook(ArrayList<Thread> snifferThs, Thread processQueueTh) {
            this.snifferThs = snifferThs;
            this.processQueueTh = processQueueTh;
        }
        
        @Override
        public void run() {
            System.out.println("Waiting Sniffer and Queue Processor to Finish...");
            for(Thread th : snifferThs) {
                if(th == null) continue;
                
                if(th.isAlive()) {
                    try {
                        th.join();
                    } catch (InterruptedException ex) {
                        Logger.getLogger(HostCapture.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
            
            if(processQueueTh.isAlive()) {
                try {
                    processQueueTh.join();
                } catch (InterruptedException ex) {
                    Logger.getLogger(HostCapture.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
            
            System.out.println("Quiting");
        }
    }
    
    public HostCapture() {
        pkt_queue = new LinkedBlockingQueue<>();
        appFrame = new AppFrame();
        processQueuePacketThread = new Thread(new ProcessQueuePackets(pkt_queue));
    }
    
    static public AppFrame getFrame() {
        return HostCapture.appFrame;
    }
    
    public void startHostCapture() {
            String dev_config = Config.getDevice();
            Sniffer sniffer;
            
            Runtime.getRuntime().addShutdownHook(new Thread(new HostCaptureShutDownHook(sniffer_threads_list,processQueuePacketThread)) );
            initUI();
            
            processQueuePacketThread.start();

            if(dev_config.equals("ASK")) {
                /**
                 * @TODO    
                */
            } else if(dev_config.equals("ALL")) {
                startSniffers(Sniffer.getInterfaces());
            } else {
                List<PcapIf> l = new ArrayList<PcapIf>() {{add(Sniffer.getDeviceFromName(dev_config));}};
                startSniffers(l);
            }
    }

    private void startSniffers(List<PcapIf> interfaces) {
        sniffer_threads_list = new ArrayList();
        
        int i=0;
        DefaultTableModel model = (DefaultTableModel) appFrame.getInterfacesTable().getModel();

        //Generating one thread per interfaces
        for (PcapIf inet : interfaces) {
            if(inet.getAddresses().isEmpty()) continue;
            sniffer_threads_list.add(new Thread(new Sniffer(inet,pkt_queue,i)));

            String ip = "";
            for (PcapAddr addr : inet.getAddresses()) {
                ip = ip + FormatUtils.ip(addr.getAddr().getData()) + "/"
                        + FormatUtils.ip(addr.getNetmask().getData()) + " "; 
            }
          
            model.addRow(new Object[]{inet.getDescription(),ip,0,0});
            i++;
        }
        
        //Starting all threads
        for(Thread sniffer_th : sniffer_threads_list) {
            sniffer_th.start();
        }

        //Waitting all thrad to end
       /* for(Thread sniffer_th : sniffer_threads_list) {
            try {
                sniffer_th.join();
            } catch (InterruptedException ex) {
                Logger.getLogger(HostCapture.class.getName()).log(Level.SEVERE, null, ex);
            }
        }*/
    }
    
    public void initUI() {
        appFrame.setVisible(true);
    }
    
    public static void main(String[] args) {

        String configFile = "config.properties";
        
        if(args.length > 0) {
            for(int i = 0; i < args.length; i++) {
                if(args[i].compareTo("-c")==0) {
                    configFile = args[i+1];
                    i++;
                }
            }
        }
        
        Config.loadConfig(configFile);

        HostCapture hc = new HostCapture();
        hc.startHostCapture();
    }
    

}
