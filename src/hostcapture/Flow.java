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
    private String http_host;
    private String http_Method;
    private String http_URL;
    private String http_UserAgent;    
    private String http_ContentType;
    private String http_Response;
    
    public static final int ROWSIZE = 180;

    public Flow(int hashID, String farIP, String protocol, int port, long ts_first_packet, long ts_last_packet, String int_name, String int_hw, long packet_count, long bytes, String http_host, String http_Method, String http_URL, String http_UserAgent, String http_ContentType, String http_Response) {
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
        this.http_host = http_host;
        this.http_Method = http_Method;
        this.http_URL = http_URL;
        this.http_UserAgent = http_UserAgent;
        this.http_ContentType = http_ContentType;
        this.http_Response = http_Response;
    }

    @Override
    public String toString() {
        return "{" + "hashID=" + String.format("%x",hashID) + ", farIP=" + farIP + ", protocol=" + protocol + ", port=" + port + ", ts_first_packet=" + ts_first_packet + 
                ", ts_last_packet=" + ts_last_packet + ", int_name=" + int_name + ", int_hw=" + int_hw + ", packet_count=" + packet_count + ", bytes=" + bytes + 
                ", http_host=" + http_host + ", http_method ="+http_Method+", http_URL="+http_URL+", http_UserAgent="+http_UserAgent+", http_ContentType="+http_ContentType+
                ", http_response="+ http_Response+'}';
    }

    public String toString(String sep) {
        return String.format("%x",hashID) + sep + farIP + sep + protocol + sep + port + sep + ts_first_packet + sep + 
                ts_last_packet + sep + int_name + sep + int_hw + sep + packet_count + sep + bytes + sep + preparString(http_host) + sep +
                preparString(http_Method) + sep + preparString(http_URL) + sep + preparString(http_UserAgent) + sep + 
                preparString(http_ContentType) + sep + preparString(http_Response);
    }

    private String preparString(String x) {
        if(x == null) {
            return "";
        }
        
        return "\""+x+"\"";
    }
    public boolean add(Flow fl) {
        
        this.packet_count += fl.getPacket_count();
        this.bytes += fl.getBytes();
        this.ts_last_packet = (this.ts_last_packet < fl.getTs_last_packet()) ? fl.getTs_last_packet() : this.ts_last_packet;
        this.http_host = (this.http_host == null && fl.getHttp_host() != null) ? fl.getHttp_host() : this.http_host;
        this.http_Method = (this.http_Method == null && fl.getHttp_Method() != null) ? fl.getHttp_Method() : this.http_Method;
        this.http_URL = (this.http_URL == null && fl.getHttp_URL() != null) ? fl.getHttp_URL() : this.http_URL;
        this.http_UserAgent = (this.http_UserAgent == null && fl.getHttp_UserAgent() != null) ? fl.getHttp_UserAgent() : this.http_UserAgent;
        this.http_ContentType = (this.http_ContentType == null && fl.getHttp_ContentType() != null) ? fl.getHttp_ContentType() : this.http_ContentType;
        this.http_Response = (this.http_Response == null && fl.getHttp_Response() != null) ? fl.getHttp_Response() : this.http_Response;
        
        return true;
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

    public String getHttp_host() {
        return http_host;
    }

    public void setHttp_host(String http_host) {
        this.http_host = http_host;
    }

    public String getHttp_Method() {
        return http_Method;
    }

    public void setHttp_Method(String http_Method) {
        this.http_Method = http_Method;
    }

    public String getHttp_URL() {
        return http_URL;
    }

    public void setHttp_URL(String http_URL) {
        this.http_URL = http_URL;
    }

    public String getHttp_UserAgent() {
        return http_UserAgent;
    }

    public void setHttp_UserAgent(String http_UserAgent) {
        this.http_UserAgent = http_UserAgent;
    }

    public String getHttp_ContentType() {
        return http_ContentType;
    }

    public void setHttp_ContentType(String http_ContentType) {
        this.http_ContentType = http_ContentType;
    }

    public String getHttp_Response() {
        return http_Response;
    }

    public void setHttp_Response(String http_Response) {
        this.http_Response = http_Response;
    }

    
    

    
}
