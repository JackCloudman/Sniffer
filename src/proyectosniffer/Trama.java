/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proyectosniffer;

import java.math.BigInteger;
import java.util.Date;
import org.jnetpcap.packet.PcapPacket;
import java.security.*;
public abstract class Trama {
    Date fecha_creacion;
    String hash;
    PcapPacket paquete;
    byte []macO,macD;
    public Trama(PcapPacket p){
        paquete = p;
        fecha_creacion = new Date();
        macD = p.getByteArray(0, 6);
        macO = p.getByteArray(6, 6);
        try{
        MessageDigest md = MessageDigest.getInstance("MD5");
        hash = new BigInteger(1,md.digest(p.getByteArray(0, p.size()))).toString(16);
        }catch(Exception e){
            System.out.println(e.toString());
            hash = fecha_creacion.toString();
        } 
    }
    public String getMacO(){
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X ",macO[0],macO[1],macO[2],macO[3],macO[4],macO[5]);
    }
    public String getMacD(){
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X ",macD[0],macD[1],macD[2],macD[3],macD[4],macD[5]);
    }
    public Date getDate(){
        return fecha_creacion;
    }
    @Override
    public abstract String toString();
    
}
