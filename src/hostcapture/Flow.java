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
    
    public static final int ROWSIZE = 180;

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
        return "{" + "hashID=" + String.format("%x",hashID) + ", farIP=" + farIP + ", protocol=" + protocol + ", port=" + port + ", ts_first_packet=" + ts_first_packet + ", ts_last_packet=" + ts_last_packet + ", int_name=" + int_name + ", int_hw=" + int_hw + ", packet_count=" + packet_count + ", bytes=" + bytes + '}';
    }

    public String toString(String sep) {
        return String.format("%x",hashID) + sep + farIP + sep + protocol + sep + port + sep + ts_first_packet + sep + 
                ts_last_packet + sep + int_name + sep + int_hw + sep + packet_count + sep + bytes;
    }
    
    public int getHashID() {
        return hashID;
    }

    public String getFarIP() {
        return farIP;
    }

    public String getProtocol() {
        return protocol;
    }

    public int getPort() {
        return port;
    }

    public long getTs_first_packet() {
        return ts_first_packet;
    }

    public long getTs_last_packet() {
        return ts_last_packet;
    }

    public String getInt_name() {
        return int_name;
    }

    public String getInt_hw() {
        return int_hw;
    }

    public long getPacket_count() {
        return packet_count;
    }

    public long getBytes() {
        return bytes;
    }

    public void setHashID(int hashID) {
        this.hashID = hashID;
    }

    public void setFarIP(String farIP) {
        this.farIP = farIP;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public void setTs_first_packet(long ts_first_packet) {
        this.ts_first_packet = ts_first_packet;
    }

    public void setTs_last_packet(long ts_last_packet) {
        this.ts_last_packet = ts_last_packet;
    }

    public void setInt_name(String int_name) {
        this.int_name = int_name;
    }

    public void setInt_hw(String int_hw) {
        this.int_hw = int_hw;
    }

    public void setPacket_count(long packet_count) {
        this.packet_count = packet_count;
    }

    public void setBytes(long bytes) {
        this.bytes = bytes;
    }


    

    
}
