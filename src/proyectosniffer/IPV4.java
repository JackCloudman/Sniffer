/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proyectosniffer;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Ip4;

/**
 *
 * @author root
 */
public class IPV4{
    
    public IPV4(PcapPacket p) {
        Ip4 ip = new Ip4();
    }
    @Override
    public String toString() {
        return "IPV4";
    }
    
}
