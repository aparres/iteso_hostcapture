/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hostcapture;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Config {
    static Properties config = new Properties(Config.buildDefaults());
    
    private static Properties buildDefaults() {
        Properties def = new Properties();
        
        def.setProperty("device", "ALL");
        def.setProperty("FilePath", "");
        def.setProperty("FileBaseName", "flows");
        def.setProperty("FileMaxSize", "10240"); 
        def.setProperty("CountFlowsWriteToFile", "100"); 
        def.setProperty("user", "unkown"); 
        
        return def;
    }
    
    static public void loadConfig(String filename) {
        try {
            config.load(new FileInputStream(new File(filename)));
        } catch (IOException ex) {
            Logger.getLogger(Config.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    static public String getDevice() {
        return config.getProperty("device");
    }
    
    static public double getTSRange() {
        return Double.parseDouble(config.getProperty("tsRange"));
    }
    
    static public String getConfig(String key) {
        return config.getProperty(key);
    }
}
