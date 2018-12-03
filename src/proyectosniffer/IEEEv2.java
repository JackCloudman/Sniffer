/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proyectosniffer;

import org.jnetpcap.packet.PcapPacket;

public class IEEEv2 extends Trama{

    public IEEEv2(PcapPacket p) {
        super(p);
        
    }
    @Override
    public String toString() {
        return "TRAMA IEEE";
    }
    
}
