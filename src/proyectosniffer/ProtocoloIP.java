package proyectosniffer;

import org.jnetpcap.packet.JPacket;

public class ProtocoloIP {
    JPacket trama;
    int protocolo;
    int indice;
    public ProtocoloIP(int protocolo, JPacket trama, int indice){
        this.protocolo = protocolo;
        this.trama = trama;
        this.indice = indice;
    }
    String llenaProtocoloIP(){
        String cadena="";
        switch(protocolo) {
            case 1: cadena = esICMP(trama); 
                    break;
            case 2: cadena = esIGMP(trama); 
                    break;
            case 6: cadena = esTCP(trama); 
                    break;
            case 17: cadena = esUDP(trama);
                     break;
            case 89: cadena = esOSPF(trama); 
                     break;
            default: cadena = "Protocolo Desconocido";
        }
        return cadena;
    }
    
    public String esICMP(JPacket trama) {
        int q = indice;
        String cadena="", aux;
        cadena += "Protocolo ICMP";
        
        
        int tipo = trama.getUByte(q);
        q++;
        cadena += "\nTipo: " + tipo;
        
        int codigo = trama.getUByte(q);
        q++;
        cadena += "\nCodigo: " + codigo + " (";
        String auxCode = "";
        
        switch(tipo) {
            case 0: auxCode = code0and8ICMP(); 
                    break;
            case 3: auxCode = code3ICMP(codigo);    
                    break;  
            case 8: auxCode = code0and8ICMP(); 
                    break;
            case 11: auxCode = code11ICMP(codigo); 
                     break;
        }        
        cadena += auxCode+")";
        
        int icmp_checksum = (trama.getUByte(q) * 256) + trama.getUByte(q + 1); 
        q += 2;
        aux = Integer.toHexString(icmp_checksum);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(int i = 0 ; i < tmp ; i++) 
                aux = '0' + aux;
        }
        cadena += "\nChecksum ICMP: 0x" + aux;
        
        switch(tipo) {
            case 0: auxCode = code0and8ICMP(trama, q); 
                    break;
            case 3: auxCode = "\nSin Uso: 0x000000"; 
                    break;
            case 8: auxCode = code0and8ICMP(trama, q); 
                    break;
            case 11: auxCode = "\nSin Uso: 0x000000"; 
                     break;
        }                        
        cadena += auxCode;
        return cadena;
    }
    
    public String esIGMP(JPacket trama){
        String cadena="Protocolo IGMP", aux;
        int q = indice, tempoq;
        boolean version = true;
        tempoq = q + 8;
        for(int i = tempoq; i < trama.size(); i++) {
            if(trama.getUByte(i) != 0) {
                version = false; // es v3
            }
        }
        if(version) { // version 2
            cadena += "\nVersion: IGMP 2 ";
            
            int tipo = trama.getUByte(q); 
            q++;
            
            cadena += "\nTipo: ";
            switch(tipo) {
                case 17: cadena += "Consulta de membresía"; 
                         break;
                case 22: cadena += "Reporte de membresía"; 
                         break;
                case 23: cadena += "Deja el grupo"; 
                         break;
            }
            aux = Integer.toHexString(tipo);
            cadena += " (0x" + aux + ")";             
            
            
            int tiempoMax = trama.getUByte(q); 
            q++;
            cadena += "\nTiempo Maximo de Respuesta: " + tiempoMax;
            
            
            int checksumIGMP = (trama.getUByte(q) * 256) + trama.getUByte(q + 1);
            q += 2;
            aux = Integer.toHexString(checksumIGMP);
            if(aux.length() < 4) {
                int tmp = 4 - aux.length();
                for(int i = 0 ; i < tmp ; i++) 
                    aux = '0' + aux;
            }
            cadena += "\nChecksum: 0x" + aux; // + "\n\tDirección Multicast: ";
            
            int groupAd[] = new int[4];
            cadena += "\nDirección Multicast: ";
            for(int i = 0; i < 4; i++) {
                groupAd[i] = trama.getUByte(q + i);
                if(i != 3) 
                    cadena += groupAd[i] + ".";
            }
            cadena += groupAd[3];
             
        } 
        else {
            cadena += "\nVersión: IGMP 3";//\n\tTipo: ";
            cadena += "Tipo: ";
            int tipo = trama.getUByte(q); q++;                
            switch(tipo) {
                case 17:
                    cadena += "Membership Query"; 
                    break;
                case 34: 
                    cadena += "Membership Report";// + es34IGMP3(paq, q); break;
                    cadena += es34IGMP3(trama, q);
            }               
        }   
        
        return cadena;
    }
    
    public String esTCP(JPacket paq) {
        int q = indice;
        String texto = "Protocolo TCP", aux1, aux2;
        texto += "\nPuerto Origen: ";        
        int puerto_o = (paq.getUByte(q) * 256) + paq.getUByte(q + 1); 
        q += 2;
        texto += puerto_o;
        int puerto_d = (paq.getUByte(q) * 256) + paq.getUByte(q + 1);
        q += 2;
        texto += "\nPuerto Destino: " + puerto_d;
        
        int num_seq1 = (paq.getUByte(q) * 256) + paq.getUByte(q + 1); 
        q += 2;
        int num_seq2 = (paq.getUByte(q) * 256) + paq.getUByte(q + 1);
        q += 2;
        aux1 = Integer.toHexString(num_seq1);
        aux2 = Integer.toHexString(num_seq2);
        if(aux1.length() < 4) {
            int tmp = 4 - aux1.length();
            for(int i = 0 ; i < tmp ; i++) 
                aux1 = '0' + aux1;
        }
        if(aux2.length() < 4) {
            int tmp = 4 - aux2.length();
            for(int i = 0 ; i < tmp ; i++) 
                aux2 = '0' + aux2;
        }
        texto += "\nNumero de Secuencia: 0x" + aux1 + aux2;
        
        int num_ack1 = (paq.getUByte(q) * 256) + paq.getUByte(q + 1);
        q += 2;
        int num_ack2 = (paq.getUByte(q) * 256) + paq.getUByte(q + 1); 
        q += 2;
        aux1 = Integer.toHexString(num_ack1);
        aux2 = Integer.toHexString(num_ack2);
        if(aux1.length() < 4) {
            int tmp = 4 - aux1.length();
            for(int i = 0 ; i < tmp ; i++) 
                aux1 = '0' + aux1;
        }
        if(aux2.length() < 4) {
            int tmp = 4 - aux2.length();
            for(int i = 0 ; i < tmp ; i++) 
                aux2 = '0' + aux2;
        }        
        texto += "\nNumbero ACK: 0x" + aux1 + aux2;
        int hlen = paq.getUByte(q) >> 4; 
        q++;
        texto += "\nLongitud de cabecera: " + (hlen * 4) + " bytes";
        String flags = Integer.toBinaryString(paq.getUByte(q)); 
        q++;
        if(flags.length() != 8) 
            flags = llenaCeros(flags);
        aux1 = flagsTCP(flags.substring(2));
        texto += "\nBanderas: " + aux1;
        int tam_ventana = (paq.getUByte(q) * 256) + paq.getUByte(q + 1);
        q += 2;
        texto += "\nTamaño de Ventana: " + tam_ventana;
        int tcp_checksum = (paq.getUByte(q) * 256) + paq.getUByte(q + 1);
        q += 2;
        aux1 = Integer.toHexString(tcp_checksum);
        if(aux1.length() < 4) {
            int tmp = 4 - aux1.length();
            for(int i = 0 ; i < tmp ; i++)
                aux1 = '0' + aux1;
        }
        texto += "\nChecksum TCP: 0x" + aux1;        
        return texto;
    }
    
    public String esUDP(JPacket paq) {
        int q = indice;
        String texto = "Protocolo UDP";
        String aux;       
        int puerto_o = (paq.getUByte(q) * 256) + paq.getUByte(q + 1); 
        q += 2;
        texto += "\nPuerto Origen: " + puerto_o;
        int puerto_d = (paq.getUByte(q) * 256) + paq.getUByte(q + 1);
        q += 2;
        texto += "\nPuerto Destino: " + puerto_d;
        int udp_len = (paq.getUByte(q) * 256) + paq.getUByte(q + 1);
        q += 2;
        texto += "\nLongitud cabecera: " + udp_len;
        int udp_checksum = (paq.getUByte(q) * 256) + paq.getUByte(q + 1); 
        q += 2;
        aux = Integer.toHexString(udp_checksum);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(int i = 0 ; i < tmp ; i++) 
                aux = '0' + aux;
        }
        texto += "\nChecksum UDP: 0x" + aux;
        return texto;
    }
    
    public String esOSPF(JPacket paq) { // Not used 
        int i;
        String texto = "\nEncabezado OSPF\nVersión OSPF: ";      
        int version = paq.getUByte(34);
        texto += version + "\nTipo de Mensaje: ";
        int tipo = paq.getUByte(35);
        texto += tipoOSPF(tipo);
        int longitud_OSPF = (256 * paq.getUByte(36)) + paq.getUByte(37);
        texto += "\nLongitud de Paquete: " + longitud_OSPF;
        texto += "\nID Router: ";
        int router_id[] = new int[4];
        for(i = 0; i < 4; i++) { // 38 - 41
            router_id[i] = paq.getUByte(38 + i);
            if(i != 3)
                texto += router_id[i] + ".";
        }
        texto += router_id[i];
        texto += "\nID Area: ";
        int area_id[] = new int[4];
        for(i = 0; i < 4; i++) { // 42 - 45
            area_id[i] = paq.getUByte(42 + i);
            if(i != 3) 
                texto += area_id[i] + ".";
        }
        texto += area_id[i];
        texto += "\nChecksum: 0x";
        int ospf_checksum = (paq.getUByte(46) * 256) + paq.getUByte(47);
        String aux = Integer.toHexString(ospf_checksum);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(i = 0 ; i < tmp ; i++) {aux = '0' + aux;}
        }
        texto += aux + "\nTipo de Autenticación: ";
        int tipAu = paq.getUByte(48);
        texto += tipAuOSPF(tipAu);
        
        return texto;
    }
    
    private String code0and8ICMP() {
        String texto = ")";        
        return texto;
    }
     private String code3ICMP(int codigo) {
        String texto = "";
        switch(codigo) {
            case 0: texto += "Red inaccesible)"; break;
            case 1: texto += "Host inaccesible)"; break;
            case 2: texto += "Protocolo inaccesible)"; break;
            case 3: texto += "Puerto inaccesible)"; break;
            case 4: texto += "DF activado)"; break;
            case 5: texto += "Fallo ruta origen)"; break;
            default: texto += "Desconocido)"; break;            
        }
        
        return texto;
    } 
     private String code11ICMP(int codigo) {
        String texto = "";
        if(codigo == 0) {
            texto += "TTL excedido en tránsito";
        } else {
            texto += "Tiempo de reensamblado excedido";
        }
        return texto;
    }
     private String code0and8ICMP(JPacket trama, int q) { // 38
        String texto = "\nIdentificador: ", aux;
        int identificador = (trama.getUByte(q) * 256) + trama.getUByte(q + 1);
        q += 2;
        texto += identificador + " (0x";
        aux = Integer.toHexString(identificador);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(int i = 0 ; i < tmp ; i++) {aux = '0' + aux;}
        }
        texto += aux + ")\nNumero de Secuencia: ";
        int seqNum = (trama.getUByte(q) * 256) + trama.getUByte(q + 1); 
        q += 2;
        aux = Integer.toHexString(seqNum);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(int i = 0 ; i < tmp ; i++) {aux = '0' + aux;}
        }
        texto += seqNum + " (0x" + aux + ")";
        texto += "\nDatos: "; aux = "";
        for(int i = 0; i < 32; i++) {
            aux += Integer.toHexString(trama.getUByte(q + i));
        }
        texto += aux;
        return texto;
    }
     
     private String es34IGMP3(JPacket paq, int q) {
        String texto = "\nReservado: ", aux = "";
        int res1 = paq.getUByte(q); 
        q++;
        texto += res1; 
        int checksumIGMP3 = (paq.getUByte(q) * 256) + paq.getUByte(q + 1); 
        q+= 2;
        aux = Integer.toHexString(checksumIGMP3);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(int i = 0 ; i < tmp ; i++) {aux = '0' + aux;}
        }
        texto += "\nChecksum IGMP3: 0x" + aux;// + "\n\tReserved: ";
        int res2 = (paq.getUByte(q) * 256) + paq.getUByte(q + 1); q += 2;
        texto = "\nReservado: " + res2; //"\n\tNumero de Registros de Grupo: ";   
        texto += "\nNumero de Grupo Record: ";
        int groupReg = (paq.getUByte(q) * 256) + paq.getUByte(q + 1); q+= 2;
        texto += groupReg;
        aux = "";
        String name="";
        for(int i = 0; i < groupReg; i++) {            
            name += "\n** REGISTRO " + (i + 1) + " **";
            aux = "Tipo Record: ";            
            int regTipo = paq.getUByte(q); q++;
            switch(regTipo) {
                case 1: aux += "Modo es incluído"; 
                        break;
                case 2: aux += "Modo es excluído"; 
                        break;
                case 3: aux += "Cambiar a modo incluído"; 
                        break;
                case 4: aux += "Cambiar a modo excluído"; 
                        break;
                case 5: aux += "Permitir nuevas fuentes"; 
                        break;
                case 6: aux += "Bloquear fuentes viejas"; 
                        break;
            }
            name += aux;
            aux = "\nAuxiliar Information Length: ";
            int auxDataL = paq.getUByte(q); q++;
            aux += auxDataL;
            name += aux;
            int numSour = (paq.getUByte(q) * 256) + paq.getUByte(q + 1); q += 2;
            aux = "\nNumber of Sources: " + numSour;
            name += aux;
            aux = "\nDirección Multicast: ";
            int multiDir[] = new int[4];
            for(int k = 0; k < 4; k++) {
                multiDir[k] = paq.getUByte(q); q++;
                if(k != 3) 
                    aux += multiDir[k] + ".";
            }
            aux += multiDir[3];
            name += aux;
            int sources[] = new int[4];
            for(int w = 0; w < numSour; w++) {
                aux = "\nOrigen: " + (w + 1);
                for(int b = 0; b < 4; b++) {
                    sources[b] = paq.getUByte(q); q++;
                    if(b != 3) 
                        aux += sources[b] + ".";
                }
                aux += sources[3];
                name+=aux;
            }            
            if(auxDataL != 0) aux = "\nInformacion Auxiliar: ";
            for(int g = 0; g < auxDataL; g++) 
                aux += Integer.toHexString(paq.getUByte(q)); q++;
            name+=aux;
        }
        texto += name;        
        return texto;
    }
    public String tipoOSPF(int tipo) {
        String texto;
        switch(tipo) {
            case 1: texto = "Saludo (" + tipo + ")"; 
                    break;
            case 2: texto = "DBD (" + tipo + ")";
                    break;
            case 3: texto = "LSR (" + tipo + ")"; 
                    break;
            case 4: texto = "LSU (" + tipo + ")"; 
                    break;
            case 5: texto = "LSAck (" + tipo + ")";
                    break;
            default: texto = "Desconocido";
                    break;
        }
        return texto;
    }
    
    private String tipAuOSPF(int tipo) {
        String texto;
        switch(tipo) {
            case 0: texto = "Sin Autenticacion."; break;
            case 1: texto = "Texto Claro."; break;
            case 2: texto = "MOS"; break;
            default: texto = "Desconocido :c"; break;
        }
        return texto;
    }
     private String llenaCeros (String binario) {
        int t_ctrl = 8 - binario.length();
        String aux = "";
        for(int b = 0 ; b < t_ctrl ; b++) {
            aux = aux.concat("0");
        }                             
        aux = aux.concat(binario);
        binario = aux.substring(0);
        return binario;
    }
    private String flagsTCP(String flags) {
        String texto = "\n\t\tURG: ";
        if(flags.charAt(0) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", ACK: ";
        if(flags.charAt(1) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", PSH: ";
        if(flags.charAt(2) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", RST: ";
        if(flags.charAt(3) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", SYN: ";
        if(flags.charAt(4) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", FIN: ";
        if(flags.charAt(5) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        
        return texto;
    }
}
