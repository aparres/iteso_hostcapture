/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hostcapture;

import java.util.HashMap;

public class Flow {

    private int hashID;
    private String farIP;
    private String protocol;
    private int port;
    private long ts_first_packet;
    private long ts_last_packet;
    private String int_name;
    private String int_hw;
    private long packet_count;
    private long bytes;

    public Flow(int hashID, String farIP, String protocol, int port, long ts_first_packet, long ts_last_packet, String int_name, String int_hw, long packet_count, long bytes) {
        this.hashID = hashID;
        this.farIP = farIP;
        this.protocol = protocol;
        this.port = port;
        this.ts_first_packet = ts_first_packet;
        this.ts_last_packet = ts_last_packet;
        this.int_name = int_name;
        this.int_hw = int_hw;
        this.packet_count = packet_count;
        this.bytes = bytes;
    }

    @Override
    public String toString() {
        return "Flow{" + "hashID=" + hashID + ", farIP=" + farIP + ", protocol=" + protocol + ", port=" + port + ", ts_first_packet=" + ts_first_packet + ", ts_last_packet=" + ts_last_packet + ", int_name=" + int_name + ", int_hw=" + int_hw + ", packet_count=" + packet_count + ", bytes=" + bytes + '}';
    }

    

    
}
