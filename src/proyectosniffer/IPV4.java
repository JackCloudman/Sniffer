/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proyectosniffer;

import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author root
 */
public class IPV4 extends Trama{
    
    public IPV4(PcapPacket p) {
        super(p);
    }

    @Override
    public String toString() {
        return "hola";
    }
    
}
