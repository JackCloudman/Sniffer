package proyectosniffer;

import org.jnetpcap.packet.JPacket;

public class IPv4 {
    JPacket trama;
    int protocolo;
    int indice;
    public IPv4(JPacket trama){
        this.trama = trama;
    }
    public int getProtocoloIP() {
        return protocolo;
    }
    public int getIndice(){
        return indice;
    }
    public String llenarIPv4(){
        String texto = "", aux;
        int version = trama.getUByte(14) >> 4;
        texto += "\nVersion: " + version;
        
        int hlen = (trama.getUByte(14) & 15) * 4;
        texto += "\nHLEN: " + hlen + " bytes";
        
        int dsf = trama.getUByte(15);
        if(String.valueOf(dsf).length() == 1) {
            aux = '0' + String.valueOf(dsf);               
        } else {
            aux = Integer.toHexString(dsf);
        }
        texto += "\nTipo de Servicio: 0x" + aux;
        
        String s_dsf = Integer.toBinaryString(dsf);
        if(s_dsf.length() != 8) { //No cuenta los ceros al inicio
            s_dsf = llenarCeros(s_dsf);
        }
        aux = precedenciaIPv4(s_dsf.substring(0, 3));        
        texto += "\nPrecedencia: " + aux;
        
        aux = caracServIPv4(s_dsf.substring(3));
        texto += "\nCaracteristica: " + aux;
        
        
        texto += "\nTamaño total: " + (trama.getUByte(16) * 256) + trama.getUByte(17);
        
        int id = (trama.getUByte(18) * 256) + trama.getUByte(19);
        texto += "\nIdentificador: 0x" + Integer.toHexString(id) + " (" + id + ")";
        
        int flags = trama.getUByte(20) & 0xE0; //11100000
        String s_flags = Integer.toBinaryString(flags);
        if(s_flags.length() != 8) { //No cuenta los ceros al inicio
            s_flags = llenarCeros(s_flags);
        }
        aux = banderasIPv4(s_flags);
        String t_b  = String.valueOf(Integer.parseInt(s_flags.substring(0,3), 2));
        if(t_b.length() == 1) {
            t_b = '0' + t_b;
        }
        
        texto += "\nBanderas: 0x" + t_b + " - "+ aux;
        
        int pos_frag = ((trama.getUByte(20) & 0x1F)  * 256) + trama.getUByte(21);
        texto += "\nBalance de Fragmentos: " + pos_frag;
        
        
        texto = "\nTiempo de vida: " + trama.getUByte(22);
        
        protocolo = trama.getUByte(23);
        aux = protocoloIPv4(protocolo);
        texto += "\nProtocolo: " + aux + " ("+ protocolo + ")";
        
        
        int checksum = (trama.getUByte(24) * 256) + trama.getUByte(25);
        texto += "\nChecksum de Cabecera: 0x" + Integer.toHexString(checksum);
        
        texto += "\nIP Origen: " + trama.getUByte(26) + "." + trama.getUByte(27) + "." + trama.getUByte(28) + "." + trama.getUByte(29);
        
        texto += "\nIP Destino: " + trama.getUByte(30) + "." + trama.getUByte(31) + "." + trama.getUByte(32) + "." + trama.getUByte(33);
        
        
        if(hlen != 20) { // Tiene opciones
            indice = 34 + (hlen - 20);
        } else {
            indice = 34;
        }       
                              
        return texto;
    }
    
    private String llenarCeros (String binario) {
        int t_ctrl = 8 - binario.length();
        String aux = "";
        for(int b = 0 ; b < t_ctrl ; b++) {
            aux = aux.concat("0");
        }                             
        aux = aux.concat(binario);
        binario = aux.substring(0);
        
        return binario;
    }
    private String precedenciaIPv4(String cmp) {
        String prec = "";        
        if(cmp.compareTo("000") == 0) { prec = "Mejor Esfuerzo"; } 
        else if(cmp.compareTo("001") == 0) { prec = "Prioridad"; } 
        else if(cmp.compareTo("010") == 0) { prec = "Inmediata"; } 
        else if(cmp.compareTo("011") == 0) { prec = "Flash"; }  
        else if(cmp.compareTo("100") == 0) { prec = "Sobreescritura Flash"; }  
        else if(cmp.compareTo("101") == 0) { prec = "Critica"; }  
        else if(cmp.compareTo("110") == 0) { prec = "Control Interred"; }  
        else if(cmp.compareTo("111") == 0) { prec = "Control de red"; } 
        
        return prec;
    }
    private String caracServIPv4(String cmp) {
        String carac = "Retardo: ";        
        if(cmp.charAt(0) == '0') { carac += "Normal"; } else { carac += "Baja";}
        carac += ", Performance: ";
        if(cmp.charAt(1) == '0') { carac += "Normal"; } else { carac += "Alta";}
        carac += ", Fidelidad: ";
        if(cmp.charAt(2) == '0') { carac += "Normal"; } else { carac += "Alta";}
        
        return carac;
    }
    private String banderasIPv4(String flags) {
        String texto = "";
        if(flags.charAt(1) == '0') {texto += "Divisible";} else {texto += "No divisible";}
        if(flags.charAt(2) == '0') {texto += ", Ultimo fragmento";} else {texto += ", Fragmento intermedio";}
        return texto;
    }
    private String protocoloIPv4(int protocolo) {
        String nombre_p = "";
        if(protocolo == 6) {nombre_p = "TCP";}
        else if(protocolo == 17) {nombre_p = "UDP";}
        return nombre_p;
    }
}
