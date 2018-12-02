/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proyectosniffer;

//Jnetpcap
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import static org.jnetpcap.packet.format.FormatUtils.asString;
import org.jnetpcap.util.PcapPacketArrayList;

public class jnetpcaphelper {
    PcapPacketArrayList packetsOffline;
    PcapPacketArrayList packetsOnline;
    StringBuilder errbuf = new StringBuilder(); // For any error msgs 
    List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs
    Pcap pcap = null;
    PcapIf device;
    ArrayList<JPacket> tramas = new ArrayList<>();
    File file;
    String mensaje="";
    int ethernet = 0;
    int ieee = 0;
    int index = 0;
    
    int flags = Pcap.MODE_PROMISCUOUS;
    int snaplen = 64 * 1024;
    int timeout = 10 * 1000;
    public jnetpcaphelper(){
    
    }
    public ArrayList<String>searchInterfaces(){
    ArrayList<String> listaInterfaces= new ArrayList<String>();
    int r = Pcap.findAllDevs(alldevs,errbuf);
    for (PcapIf device : alldevs) {
        String descripcion =
            (device.getDescription() != null) ? device.getDescription(): device.getName();
            byte[] mac = null;
                try {
                        mac = device.getHardwareAddress();
                    }catch (IOException ex) {
                        Logger.getLogger(Interfaz.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    String dir_mac = (mac==null)?"---":asString(mac);
                    listaInterfaces.add(descripcion+" MAC: "+dir_mac);
		}
    return listaInterfaces;
    }
}
