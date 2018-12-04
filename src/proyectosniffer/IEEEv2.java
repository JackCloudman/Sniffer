/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package proyectosniffer;

import org.jnetpcap.packet.PcapPacket;

public class IEEEv2 extends Trama{
    String informacion;
    public IEEEv2(PcapPacket p) {
        super(p);
        informacion = getInformacion();
    }
    public String getInformacion(){
        String codigo;
        String ieee="";
        ieee+="Longitud de la trama: ";
        int llc_length=(this.paquete.getUByte(12)*256 + this.paquete.getUByte(13));
        ieee+= llc_length+" Bytes";
        String dsap = Integer.toBinaryString(this.paquete.getUByte(14));
        if(dsap.charAt(dsap.length() - 1) == '0') {
            ieee += "\nDSAP: " + dsap + " (Dirección Individual)";
        } else {
            ieee += "\nDSAP: " + dsap + " (Dirección en Grupo)";
        }        
        String ssap = Integer.toBinaryString(this.paquete.getUByte(15));
        int flag_lsb = 0;
        if(ssap.charAt(ssap.length() - 1) == '0') {
            ieee += "\nSSAP: " + ssap + " (Paquete de Comando)";
        } else {
            ieee += "\nSSAP: " + ssap + " (Paquete de Respuesta)";
            flag_lsb = 1;   
        }
        
        if(llc_length > 3) { //Control length = 2 bytes.
            String c1 = Integer.toBinaryString(this.paquete.getUByte(16));
            if(c1.length() != 8) {
                c1 = fillZ(c1);
            }
            String c2 = Integer.toBinaryString(this.paquete.getUByte(17));
            if(c2.length() != 8) {
                c2 = fillZ(c2);
            }
            ieee+= "\nControl Bits: " +  c1 + c2;            
            char tipo = c1.charAt(c1.length() - 1);
            if(tipo == '0') { //Information
                ieee+="\nInformation: ";
                ieee+="\nN(S): "+ c1.substring(0, 7) + "N(R): "+ c2.substring(0, 7);
                ieee+="\nP/F: "+c2.charAt(7);
            } 
            else {
                char tipo_dif = c1.charAt(c1.length() - 2);
                if(tipo_dif == '0') { //Supervisory
                    ieee += "\nTipo: Supervisión \nCódigo: ";                    
                    codigo = c1.substring(4, 6);
                    switch (codigo) {
                        case "00":
                            ieee += "RR. ";
                            break;
                        case "10": //It changes!! The string is not inverted.
                            ieee += "REJ. ";
                            break;
                        case "01":
                            ieee += "RNR. ";
                        default:
                            ieee += "SREJ. ";
                    }
                    ieee += "\nN(R): " + c2.substring(0, 7);
                    ieee += "\nP/F: " + c2.charAt(7);
                } else { //Unnumbered
                    ieee += "\nTipo: Sin Numerar "; 
                    String tt = c1.substring(0, 3) + c1.substring(4, 6);
                    codigo = invierte(tt);                            
                    String nombreCodigo = getCodeUn(codigo, flag_lsb);
                    ieee += "\nNombre: " + nombreCodigo;
                }
            }
        } else { //Control length = 1 byte.
            String ctr = Integer.toBinaryString(this.paquete.getUByte(16));
            if(ctr.length() != 8) {
                ctr = fillZ(ctr);
            }
            char tipo = ctr.charAt(ctr.length() - 1);
            ieee += "\nControl Bits: " + ctr;
            if(tipo == '0') { //informacion
                ieee += "\nTipo: Informacion";               
                ieee += "\nN(S): " + ctr.substring(4, 7) + " N(R): " + ctr.substring(0, 3);
            } else {
                char tipo_dif = ctr.charAt(ctr.length() - 2);
                if(tipo_dif == '0') { // supervision
                    ieee += "\nTipo: Supervisión. ";                   
                    codigo = ctr.substring(4, 6);
                    ieee+="\nCódigo: ";
                    switch (codigo) {
                        case "00":
                            ieee += "RR.";
                            break;
                        case "10": //It changes!! The string is not inverted.
                            ieee += "REJ.";
                            break;
                        case "01":
                            ieee += "RNR.";
                        default:
                            ieee += "SREJ.";
                    }
                    ieee += "\nN(R): " + ctr.substring(0, 3);
                } else { // no numearad
                    ieee += "\nTipo: No numerada";
                    String tt = ctr.substring(0, 3) + ctr.substring(4, 6);
                    codigo = invierte(tt);                            
                    String nombreCodigo = getCodeUn(codigo, flag_lsb);
                    ieee += "\nName: " + nombreCodigo;
                }
            }
            ieee += "\nP/F: " + ctr.charAt(3);
        }
        return ieee;
    }
    private String fillZ(String binary) {
        int t_ctrl = 8 - binary.length();
        String tempo = "";
        for(int b = 0 ; b < t_ctrl ; b++) {
            tempo = tempo.concat("0");
        }                             
        tempo = tempo.concat(binary);
        binary = tempo.substring(0);
        
        return binary;
    }
    private String invierte(String str) {
        int i;
        char temp;
        String temp2, back = "";
            //Programa
            for(i = str.length(); i > 0 ; i--){
                temp = str.charAt(i-1);
                temp2 = new String(new char[] {temp}); //Se hace un 'cast' para poder concatenar
                back = back.concat(temp2);
            }           
        return back;
    }
    private String getCodeUn(String code, int flag) {
        String name;
        if(flag == 0) { //Command
            switch(code) {
                case "00001":
                    name = "SNRM";
                    break;
                case "11011":
                    name = "SNRME";
                    break;
                case "11000":
                    name = "SARM";
                    break;
                case "11100":
                    name = "SABM";
                    break;
                case "11110":
                    name = "SABME";
                    break;
                case "00000":
                    name = "UI";
                    break;
                case "00010":
                    name = "DISC";
                    break;
                case "11001":
                    name = "RSET";
                    break;
                case "11101":
                    name = "XID";
                    break;
                default:
                    name = "Desconocida";
                    break;
            }
        } else {//Response
            switch(code) {                
                case "11000":
                    name = "DM";
                    break;               
                case "00000":
                    name = "UI";
                    break;
                case "00110":
                    name = "UA";
                    break;
                case "RD":
                    name = "DISC";
                    break;                
                case "11101":
                    name = "XID";
                    break;
                default:
                    name = "Desconocida";
                    break;
            }
        }
        return name;
    }
    @Override
    public String toString() {
        return informacion;
    }
    
}
