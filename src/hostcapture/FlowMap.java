/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hostcapture;

import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author parres
 */
public class FlowMap {
    
    private Map<Integer,Flow> flows;
    private double count;

    public FlowMap() {
        this.flows = new HashMap();
        this.count = 0;
    }
    
    public long add(Flow flow){
        
        if(flows.containsKey(flow.getHashID())) {
            Flow FlowFromMap = flows.get(flow.getHashID());
            FlowFromMap.add(flow);
            
            flows.replace(FlowFromMap.getHashID(), FlowFromMap);
            
            return FlowFromMap.getPacket_count();
        } else {
            flows.put(flow.getHashID(), flow);
            this.count++;
            return 1;
        }
    }
    
    public double count() {
        return this.count;
    }
    
    public double getTsRange() {
        double minTS = 0;
        double maxTS = 0;
            

        for(Flow flow : flows.values()) {
            if(minTS == 0) {
                minTS = flow.getTs_first_packet();
                maxTS = flow.getTs_last_packet();
                continue;
            }
            
            minTS = (flow.getTs_first_packet() < minTS ) ? flow.getTs_first_packet() : minTS;
            maxTS = (flow.getTs_last_packet() > maxTS ) ? flow.getTs_last_packet() : maxTS;
        }
 
            
        return (maxTS - minTS)/1000;
                
                
    }

    @Override
    public String toString() {
        String line = new String();
        
        for(Flow flow : flows.values()) {
            line += flow.toString()+"\n";
        }
        return line;
    }

    public String toSCV() {
        return this.toSCV(",");
    }
    
    public String toSCV(String sep) {
        String line = new String();
        
        for(Flow flow : flows.values()) {
           line += flow.toString(sep) + "\n";
        }
    
        return line;
    }    
}
