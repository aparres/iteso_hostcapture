package hostcapture;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.DefaultListModel;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.ListModel;
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
    
    public HostCapture() {
        pkt_queue = new LinkedBlockingQueue<>();
        appFrame = new AppFrame();
    }
    
    static public AppFrame getFrame() {
        return HostCapture.appFrame;
    }
    
    public void startHostCapture() {
            String dev_config = Config.getDevice();
            Sniffer sniffer;
            
            initUI();
            
            Thread  t = new Thread(new ProcessQueuePackets(pkt_queue));
            t.start();

            if(dev_config.equals("ASK")) {
                String device_name = getCaptureInterface();
                sniffer = new Sniffer(device_name,pkt_queue,0);
                sniffer.startSniffer();
            } else if(dev_config.equals("ALL")) {
                startSniffers();
            } else {
                sniffer = new Sniffer(dev_config,pkt_queue,0);
                sniffer.startSniffer();
            }
       
    }

    private void startSniffers() {
        sniffer_threads_list = new ArrayList();
        List<PcapIf> interfaces = Sniffer.getInterfacesName();
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
        for(Thread sniffer_th : sniffer_threads_list) {
            try {
                sniffer_th.join();
            } catch (InterruptedException ex) {
                Logger.getLogger(HostCapture.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    private String getCaptureInterface() {
        int i = 0;
        List<PcapIf> interfaces = Sniffer.getInterfacesName();
        List<String> devices = new ArrayList();
        int device;
        Scanner in = new Scanner(System.in);
        
        System.out.println("List of interfaces ");
        
        for (PcapIf inet : interfaces) {
            
            if(inet.getAddresses().isEmpty()) continue;
            
            devices.add(inet.getName());
            String ip = "";
            for (PcapAddr addr : inet.getAddresses()) {
                ip = ip + FormatUtils.ip(addr.getAddr().getData()) + "/"
                        + FormatUtils.ip(addr.getNetmask().getData()) + " "; 
            }
            
            System.out.println("\n"+i+") "+inet.getDescription()+" ("+ip+")");
            i++;
        }
        
        System.out.print("Please select the capture interface: ");
        device = in.nextInt();
                  
        return devices.get(device);
    }  
    
    public void initUI() {
        appFrame.setVisible(true);
    }
    
    public static void main(String[] args) {
            HostCapture hc = new HostCapture();

            Config.loadConfig("config.properties");
            hc.startHostCapture();
    }
    

}
