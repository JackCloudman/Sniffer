package proyectosniffer;

import org.jnetpcap.packet.JPacket;

public class ARP {
    JPacket trama;
    public ARP(JPacket trama){
        this.trama = trama;
    }
    public String llenaARP(){
        String texto="";
        texto += "\nTipo de Hardware: ";
        String aux, aux2;
        int hard_type = (trama.getUByte(14) * 256) + trama.getUByte(15);
        aux = hardwareTypeARP(hard_type);
        texto += aux;
        int prot_type = (trama.getUByte(16) * 256) + trama.getUByte(17);
        aux2 = Integer.toHexString(prot_type);
        if(aux2.length() < 4) {
            int tmp = 4 - aux2.length();
            for(int i = 0; i < tmp; i++) 
                aux2 = '0' + aux2;
        }
        aux = protocolTypeARP(prot_type);
        texto += "\nProtocol Type: " + aux + " (0x" + aux2 + ")";
        texto += "\nTamaño de Hardware: " + trama.getUByte(18);
        texto += "\nTamaño de Protocolo: " + trama.getUByte(19);
        int opcode = (trama.getUByte(20) * 256) + trama.getUByte(21);
        aux = opcodeARP(opcode);
        texto += "\nCodigo de Operacion: " + aux + " (" + opcode + ")"; 
        aux = "";
        for(int i = 22; i < 28; i++)
            aux += String.format("%02X", trama.getUByte(i)) + ":";   
        texto += "\nMAC Origen: " + aux;
        texto += "\nIP Origen: " + trama.getUByte(28) + "." + trama.getUByte(29) + "." + trama.getUByte(30) + "." + trama.getUByte(31);
        aux = "";
        for(int i = 32; i < 38; i++)
            aux += String.format("%02X", trama.getUByte(i)) + ":";  
        texto += "\nMAC Destino: " + aux;
        texto += "\nIP Destino: " + trama.getUByte(38) + "." + trama.getUByte(39) + "." + trama.getUByte(40) + "." + trama.getUByte(41);
        return texto;
    }
    
    private String hardwareTypeARP(int type) {
        String texto = "";
        switch(type) {
            case 0: texto = "Reservado";
                    break;
            case 1: texto = "Ethernet";
                    break;
            case 6: texto = "IEEE 802"; 
                    break;
            case 7: texto = "ARCNET";
                    break;
            case 15: texto = "Frame Relay";
                     break;
            case 16: texto = "ATM"; 
                     break;
            case 17: texto = "HDLC"; 
                     break;
            case 18: texto = "Chanal Mentiroso"; 
                     break;
            case 20: texto = "Serial";
                     break;
            default: texto = "Otro";
                     break;
        }
        return texto;
    }
    private String protocolTypeARP(int type) {
        String texto = "";
        switch (type) {
            case 2048:
                texto = "IPv4";
                break;
            case 34525:
                texto = "IPv6";
                break;
            default:
                texto = "Other";
                break;
        }
        return texto;
    }
    private String opcodeARP(int opcode) {
        String texto = "";
        switch(opcode) {
            case 1: texto = "Peticion ARP"; break;
            case 2: texto = "Respuesta ARP"; break;
            case 3: texto = "Peticion RARP"; break;
            case 4: texto = "Respuesta RARP"; break;
            case 5: texto = "Peticion DRARP"; break;
            case 6: texto = "Respuesta DRARP"; break;
            case 7: texto = "Error DRARP"; break;
            case 8: texto = "Peticion InARP"; break;
            case 9: texto = "Respuesta InARP"; break;
            
        }
        return texto;
    }
}
