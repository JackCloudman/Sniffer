/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proyectosniffer;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 *
 * @author root
 */
public class ETHERNET extends Trama{
    Ip4 ip=null;
    String informacion;
    
    public ETHERNET(PcapPacket p) {
        super(p);
        if(super.tipo==2054){
            System.out.println("Procolo ARP");
        }
        else if(super.tipo == 2048){
            System.out.println("Protocolo IPV4");
            ip = new Ip4();
            super.paquete.hasHeader(ip);
        }
        informacion = getInformacion();
    }
    protected String getInformacion() {
        String s;
        if(ip!=null){
            s = "Version ip: "+ip.version()+
            "\nLongitud del encabezado: "+ip.hlen()+
            "\nTipo de servicio: "+ip.tos()+
            "\nIdentificador: "+ip.id()+
            "\nMás Fragmentos: "+ip.flags_MF()+
            "\nÚltimo fragmento: "+ip.flags_DF()+
            "\nDesplazamiento: "+ip.offset()+
            "\nTiempo de vida: "+ip.ttl()+
            "\nProtocolo: "+ip.type()+
            "\nHeader checksum: "+ip.checksum()+
            "\nIp Origen: ";
            
            for(byte b:ip.source()){
            s = s+ (b<0?(b+256)+".":b+".");
            }
            s =  s.substring(0, s.length() - 1);
            s = s+"\nIP destino: ";
            for(byte b:ip.destination()){
            s = s+ (b<0?(b+256)+".":b+".");
            }
            s =  s.substring(0, s.length() - 1);
            s = s+"\n";
            if(ip.type()==2)
             {
                s = s+"Protocolo IGMP";
                
                int suma=(ip.hlen()*4)+14;
                int IgmpTipo=super.paquete.getUByte(suma);
                System.out.println("\nIGMP tipo: "+IgmpTipo);
                switch(IgmpTipo)
                {
                    case(17):
                        s = s+"\nConsulta\n Tiempo:"+this.paquete.getUByte(suma+1);
                        break;
                    case(18):
                        s = s+"\nReporte IGMPv1\n";
                        break;
                    case(22):
                        s = s+"\nReporte IGMPv2\n";
                        break;
                    case(34):
                        s = s+"\nReporte IGMPv3\n";
                        break;
                }
                s = s+String.format("Checksum: %02x %02x\n",this.paquete.getUByte(suma+2),this.paquete.getUByte(suma+3));
                suma=suma+3;
                s = s+"Direccion de grupo: ";
                    for(int j=1; j<5; j++){
                        s = s+String.format("%d",this.paquete.getUByte(suma+j));   
                        if(j<4)
                            System.out.printf(".");
                    }
                                          
            }
            else if(ip.type()==1){
                s = s+"Protocolo: ICMP";
                Icmp icmp=new Icmp();
                if(this.paquete.hasHeader(icmp) ){
                   s = s+"Tipo: "+icmp.type()+
                    "\nCodigo: "+icmp.code()+
                    "\nChecksum: "+icmp.checksum()+
                    "\nSignificado: "+icmp.typeDescription();
                }
            }
            else if(ip.type()==6){
		Tcp tcp = new Tcp();
		if (this.paquete.hasHeader(tcp)) {
                    s=s+"Protocolo TCP\n"+
                    "=== ENCABEZADO TCP ==="+
                    "\n Puerto Origen: " + tcp.source()+
                    "\n Puerto Destino: " + tcp.destination()+
                    "\n Numero de sequencia: "+String.format("%02X",tcp.seq())+
                    "\n Numero de acuse: "+ String.format("%02X ", tcp.ack())+
                    "\n Offset: " + tcp.hlen()+
                    "\n Reservado: " + tcp.reserved()+
                    "\n Flags:\nEstado - Descripcion"+
                    tcp.flags_CWR() + " - CWR\n"+
                    tcp.flags_ECE() + " - ECN Echo (ECE)\n"+
                    tcp.flags_URG() + " - Urgente URG\n"+
                    tcp.flags_ACK() + " - Acuse ACK\n"+
                    tcp.flags_PSH() + " - Push\n"+
                    tcp.flags_RST() + " - Reset\nm"+
                    tcp.flags_SYN() + " - Synchronize\n"+
                    tcp.flags_FIN() + " - FIN"+
                    "\nVentana: " + tcp.window()+
                    "\n Checksum: "+ String.format("%02X ", tcp.calculateChecksum())+
                    "\n Urgent Point: " + tcp.urgent();
                }
                
            }
            else if(ip.type()==17){
                s = s+"Procolo: UDP";
                Udp udp = new Udp();
		if (this.paquete.hasHeader(udp)) {
                s = s+"\n Puerto Origen: " + udp.source()+
                "\n Puerto Destino: " + udp.destination()+
                "\n Longitud: " + udp.length()+
                "\n Checksum: ";
                s = s+ String.format("%02x", udp.calculateChecksum());									}
            }
            return s;
            
        }
        return "Trama ethernet";
    }

    @Override
    public String toString() {
        return informacion;
    }
    
}
