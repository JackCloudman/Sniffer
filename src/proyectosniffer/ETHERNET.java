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
public class ETHERNET extends Trama{
    
    public ETHERNET(PcapPacket p) {
        super(p);
        if(super.tipo==2054){
            System.out.println("Procolo ARP");
        }
        else if(super.tipo == 2048){
            System.out.println("Protocolo IPV4");
        }
    }
    @Override
    public String toString() {
        return "Trama ethernet";
    }
    
}
