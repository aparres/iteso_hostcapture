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

    public FlowMap() {
        this.flows = new HashMap();
    }

    public long add(Flow flow){
        
        if(flows.containsKey(flow.getHashID())) {
            Flow ActualFlow = flows.get(flow.getHashID());
            ActualFlow.setPacket_count(ActualFlow.getPacket_count() + flow.getPacket_count());
            ActualFlow.setBytes(ActualFlow.getBytes() + flow.getBytes());
            ActualFlow.setTs_last_packet(flow.getTs_first_packet());
            
            flows.replace(ActualFlow.getHashID(), ActualFlow);
            
            return ActualFlow.getPacket_count();
        } else {
            flows.put(flow.getHashID(), flow);
            return 1;
        }
    }

    @Override
    public String toString() {
        String line = new String();
        
        for(Flow flow : flows.values()) {
            line += flow.toString()+"\n";
        }
        return line;
    }
    
    
}
