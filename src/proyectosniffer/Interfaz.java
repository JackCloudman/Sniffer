package proyectosniffer;

import java.awt.Image;
import java.awt.Toolkit;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFileChooser;
import javax.swing.SwingWorker;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.jnetpcap.JBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import static org.jnetpcap.packet.format.FormatUtils.asString;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.util.PcapPacketArrayList;


public class Interfaz extends javax.swing.JFrame {
    PcapPacketArrayList packetsOffline;
    PcapPacketArrayList packetsOnline;
    StringBuilder errbuf = new StringBuilder(); // For any error msgs 
    List<PcapIf> alldevs = new ArrayList<>(); // Will be filled with NICs
    Pcap pcap = null;
    PcapIf device;
    ArrayList<JPacket> tramas = new ArrayList<>();
    
    File file;
    
    String mensaje="";
    int ethernet = 0;
    int ieee = 0;
    int index = 0;
    
    int flags = Pcap.MODE_PROMISCUOUS;
    int snaplen = 64 * 1024;
    int timeout = 10 * 1000;
    
    public Interfaz() {
        initComponents();
        jLabelInterfaz.setVisible(false);
        jComboBoxInterfaz.setVisible(false);
        jButtonAbrir.setVisible(false);
        jScrollPane1.setVisible(false);
        jButtonEmpezar.setVisible(false);
        jButtonPausar.setVisible(false);
        jButtonGuardar.setEnabled(false);
        jButtonInfo.setEnabled(false);
        jLabelEdo.setVisible(false);
        jButtonGraficar.setVisible(false);
    }
    
   // @Override
   /* public Image getIconImage(){
        Image im = Toolkit.getDefaultToolkit().getImage(ClassLoader.getSystemResource("imagenes/logo.png"));
        return im;
    }
   */
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jButtonGraficar = new javax.swing.JButton();
        jButtonLimpiar = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        jButtonAbrir = new javax.swing.JButton();
        jButton1 = new javax.swing.JButton();
        jLabelInterfaz = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jComboBoxInterfaz = new javax.swing.JComboBox<>();
        jLabel3 = new javax.swing.JLabel();
        jComboBoxTipoCaptura = new javax.swing.JComboBox<>();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTextAreaInfo = new javax.swing.JTextArea();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextAreaInfoDevice = new javax.swing.JTextArea();
        jLabelEdo = new javax.swing.JLabel();
        jButtonEmpezar = new javax.swing.JButton();
        jButtonGuardar = new javax.swing.JButton();
        jButtonInfo = new javax.swing.JButton();
        jButtonPausar = new javax.swing.JButton();

        jButtonGraficar.setBackground(new java.awt.Color(51, 51, 51));
        jButtonGraficar.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jButtonGraficar.setForeground(new java.awt.Color(0, 153, 255));
        jButtonGraficar.setText("Graficar");
        jButtonGraficar.setActionCommand("Empezar");
        jButtonGraficar.setBorder(null);
        jButtonGraficar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonGraficarActionPerformed(evt);
            }
        });

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Sniffer");
        setBackground(java.awt.SystemColor.textText);
        setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
        setForeground(java.awt.Color.gray);
        setIconImage(getIconImage());
        setUndecorated(true);
        getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jButtonLimpiar.setBackground(new java.awt.Color(51, 51, 51));
        jButtonLimpiar.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jButtonLimpiar.setText("Limpiar salida");
        jButtonLimpiar.setActionCommand("Empezar");
        jButtonLimpiar.setBorder(null);
        jButtonLimpiar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonLimpiarActionPerformed(evt);
            }
        });
        getContentPane().add(jButtonLimpiar, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 560, 200, 30));

        jLabel4.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jLabel4.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel4.setText("Información de la trama:");
        jLabel4.setToolTipText("");
        getContentPane().add(jLabel4, new org.netbeans.lib.awtextra.AbsoluteConstraints(610, 280, 320, 30));

        jButtonAbrir.setBackground(new java.awt.Color(51, 51, 51));
        jButtonAbrir.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jButtonAbrir.setBorder(null);
        jButtonAbrir.setLabel("Abrir archivo");
        jButtonAbrir.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonAbrirActionPerformed(evt);
            }
        });
        getContentPane().add(jButtonAbrir, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 270, 200, 30));

        jButton1.setBackground(new java.awt.Color(0, 0, 0));
        jButton1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/imagenes/salir.png"))); // NOI18N
        jButton1.setBorder(null);
        jButton1.setBorderPainted(false);
        jButton1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButton1ActionPerformed(evt);
            }
        });
        getContentPane().add(jButton1, new org.netbeans.lib.awtextra.AbsoluteConstraints(1060, 0, 30, 20));

        jLabelInterfaz.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jLabelInterfaz.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabelInterfaz.setText("Seleccione una interfaz de red:");
        getContentPane().add(jLabelInterfaz, new org.netbeans.lib.awtextra.AbsoluteConstraints(530, 130, 320, 30));

        jLabel2.setFont(new java.awt.Font("Consolas", 1, 36)); // NOI18N
        jLabel2.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        jLabel2.setText("Analizador de paquetes");
        getContentPane().add(jLabel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(250, 60, 580, 30));

        jComboBoxInterfaz.setBackground(new java.awt.Color(51, 51, 51));
        jComboBoxInterfaz.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jComboBoxInterfaz.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Seleccione un dispositivo" }));
        jComboBoxInterfaz.setOpaque(false);
        jComboBoxInterfaz.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxInterfazActionPerformed(evt);
            }
        });
        getContentPane().add(jComboBoxInterfaz, new org.netbeans.lib.awtextra.AbsoluteConstraints(530, 170, 310, -1));

        jLabel3.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jLabel3.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabel3.setText("Modo de captura de paquetes:");
        jLabel3.setToolTipText("");
        getContentPane().add(jLabel3, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 130, 320, 30));

        jComboBoxTipoCaptura.setBackground(new java.awt.Color(51, 51, 51));
        jComboBoxTipoCaptura.setFont(new java.awt.Font("Arial", 1, 18)); // NOI18N
        jComboBoxTipoCaptura.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "-Seleccione una opción-", "Al vuelo", "Desde un archivo" }));
        jComboBoxTipoCaptura.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBoxTipoCapturaActionPerformed(evt);
            }
        });
        getContentPane().add(jComboBoxTipoCaptura, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 170, 280, -1));

        jTextAreaInfo.setEditable(false);
        jTextAreaInfo.setBackground(new java.awt.Color(51, 51, 51));
        jTextAreaInfo.setColumns(20);
        jTextAreaInfo.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jTextAreaInfo.setForeground(new java.awt.Color(0, 153, 255));
        jTextAreaInfo.setRows(5);
        jScrollPane2.setViewportView(jTextAreaInfo);

        getContentPane().add(jScrollPane2, new org.netbeans.lib.awtextra.AbsoluteConstraints(520, 330, 490, 220));

        jTextAreaInfoDevice.setEditable(false);
        jTextAreaInfoDevice.setBackground(new java.awt.Color(51, 51, 51));
        jTextAreaInfoDevice.setColumns(20);
        jTextAreaInfoDevice.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jTextAreaInfoDevice.setForeground(new java.awt.Color(0, 153, 255));
        jTextAreaInfoDevice.setRows(5);
        jScrollPane1.setViewportView(jTextAreaInfoDevice);

        getContentPane().add(jScrollPane1, new org.netbeans.lib.awtextra.AbsoluteConstraints(10, 330, 490, 220));

        jLabelEdo.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jLabelEdo.setForeground(new java.awt.Color(0, 153, 255));
        jLabelEdo.setHorizontalAlignment(javax.swing.SwingConstants.LEFT);
        jLabelEdo.setText(".");
        getContentPane().add(jLabelEdo, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 210, 320, 30));

        jButtonEmpezar.setBackground(new java.awt.Color(51, 51, 51));
        jButtonEmpezar.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jButtonEmpezar.setText("Empezar a capturar");
        jButtonEmpezar.setActionCommand("Empezar");
        jButtonEmpezar.setBorder(null);
        jButtonEmpezar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonEmpezarActionPerformed(evt);
            }
        });
        getContentPane().add(jButtonEmpezar, new org.netbeans.lib.awtextra.AbsoluteConstraints(230, 560, 200, 30));

        jButtonGuardar.setBackground(new java.awt.Color(51, 51, 51));
        jButtonGuardar.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jButtonGuardar.setText("Guardar captura");
        jButtonGuardar.setBorder(null);
        jButtonGuardar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonGuardarActionPerformed(evt);
            }
        });
        getContentPane().add(jButtonGuardar, new org.netbeans.lib.awtextra.AbsoluteConstraints(650, 560, 170, 30));

        jButtonInfo.setBackground(new java.awt.Color(51, 51, 51));
        jButtonInfo.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jButtonInfo.setText("Más información");
        jButtonInfo.setBorder(null);
        jButtonInfo.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonInfoActionPerformed(evt);
            }
        });
        getContentPane().add(jButtonInfo, new org.netbeans.lib.awtextra.AbsoluteConstraints(830, 560, 170, 30));

        jButtonPausar.setBackground(new java.awt.Color(51, 51, 51));
        jButtonPausar.setFont(new java.awt.Font("Consolas", 1, 18)); // NOI18N
        jButtonPausar.setText("Parar captura");
        jButtonPausar.setBorder(null);
        jButtonPausar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonPausarActionPerformed(evt);
            }
        });
        getContentPane().add(jButtonPausar, new org.netbeans.lib.awtextra.AbsoluteConstraints(440, 560, 200, 30));

        pack();
        setLocationRelativeTo(null);
    }// </editor-fold>//GEN-END:initComponents

    private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButton1ActionPerformed
        System.exit(0);
    }//GEN-LAST:event_jButton1ActionPerformed

    private void jComboBoxTipoCapturaActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxTipoCapturaActionPerformed
        
        switch((String)this.jComboBoxTipoCaptura.getSelectedItem()){
            case "Desde un archivo":
                ini();
                jLabelInterfaz.setVisible(false);
                jComboBoxInterfaz.setVisible(false);
                jButtonAbrir.setVisible(true);
                jScrollPane1.setVisible(false);
                jButtonEmpezar.setVisible(false);
                jButtonPausar.setVisible(false);
                jButtonPausar.setEnabled(false);
                jButtonEmpezar.setEnabled(false);
                jButtonGuardar.setEnabled(false);
                jButtonInfo.setEnabled(true);
                jTextAreaInfo.setText("");
                jLabelEdo.setVisible(true);
                jButtonGraficar.setVisible(false);
                abrirArchivo();               
                break;
                 
             case "Al vuelo":
                //paquetes al vuelo
                 ini();
                int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
                    System.err.printf("No se pueden leer la lista de dispositivos error: %s", errbuf.toString());
		}                 
                //mostrar devices
                int i = 0;
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : device.getName();
                        byte[] mac = null;
                        try {
                            mac = device.getHardwareAddress();
                        } catch (IOException ex) {
                            Logger.getLogger(Interfaz.class.getName()).log(Level.SEVERE, null, ex);
                        }
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        System.out.printf("#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                        if(!existe(description)){
                            jComboBoxInterfaz.addItem(description+" "+dir_mac);
                        }
                         List<PcapAddr> direcciones = device.getAddresses();
                        for(PcapAddr direccion:direcciones){
                            System.out.println(direccion.getAddr().toString());
                        }//foreach

		}//for
                jLabelEdo.setVisible(false);
                jLabelInterfaz.setVisible(true);
                 jComboBoxInterfaz.setVisible(true);
                 jButtonAbrir.setVisible(false);
                jScrollPane1.setVisible(false);
                jButtonEmpezar.setVisible(false);
                jButtonPausar.setVisible(false);
                jButtonPausar.setEnabled(false);
                jButtonEmpezar.setEnabled(false);
                jButtonGuardar.setEnabled(false);
                jButtonInfo.setEnabled(false);
                jTextAreaInfo.setText("");
                jButtonGraficar.setVisible(false);
                break;
             default:
                 jLabelEdo.setVisible(false);
                 jLabelInterfaz.setVisible(false);
                 jComboBoxInterfaz.setVisible(false);
                 jButtonAbrir.setVisible(false);
                 jScrollPane1.setVisible(false);
                 jButtonEmpezar.setVisible(false);
                jButtonPausar.setVisible(false);
                jButtonPausar.setEnabled(false);
                jButtonEmpezar.setEnabled(false);
                jButtonGuardar.setEnabled(false);
                jButtonInfo.setEnabled(false);
                jTextAreaInfo.setText("");
                jButtonGraficar.setVisible(false);
                 break;
         }
    }//GEN-LAST:event_jComboBoxTipoCapturaActionPerformed
    private void abrirArchivo(){
        jLabelEdo.setText("Leyendo archivo espere...");
        errbuf = new StringBuilder(); // For any error msgs 
        String archivo = null;
        //abrir archivo
        JFileChooser fileopen = new JFileChooser("C:\\Escom\\Redes");
        FileNameExtensionFilter filtroPcap = new FileNameExtensionFilter("*.PCAP", "pcap", ".pcap");
        fileopen.setFileFilter(filtroPcap);
        fileopen.showOpenDialog(this);
        try{
            archivo = fileopen.getSelectedFile().getAbsolutePath();
        }catch(Exception e){
            System.err.println(e);
        }
        try{
            pcap = Pcap.openOffline(archivo, errbuf);
        }catch(Exception e){
            System.out.println(e);
        }
        capturaArchivo();
    }
    
    private void capturaArchivo(){
        ini();
        packetsOffline = new PcapPacketArrayList();
            PcapPacketHandler<PcapPacketArrayList> jpacketHandler = (PcapPacket packet, PcapPacketArrayList PaketsList) -> {
            PaketsList.add(packet);
        };
        try {
            pcap.loop(-1, jpacketHandler, packetsOffline);
            //return packets;
        } finally {
            pcap.close();
        }
        for (int i = 0; i < packetsOffline.size(); i++) {
            llenar(packetsOffline.get(i));
        }
          

        System.out.println("Ethernet: " + ethernet);
        System.out.println("IEEE: " + ieee);
        /*Data e = new Data("Ethernet", ethernet);
        Data i = new Data("IEEE", ieee);
        if (ethernet != 0) {
            datos.add(e);
        }
        if (ieee != 0) {
            datos.add(i);
        }
        ArrayList<Data> source = deleteDuplicate(destinos);
        ArrayList<Data> from = deleteDuplicate(origin);
        for (int j = 0; j < source.size(); j++) {
        System.out.println("Sources" + source.get(j));
        }

        for (int j = 0; j < source.size(); j++) {
            System.out.println("Origenes" + from.get(j));
        }*/
    }
    private void llenar(JPacket packet){
        jLabelEdo.setText("Leyendo archivo espere...");
        String data_table[] = new String[5];
        String tempo = "";
       tramas.add(packet);
        data_table[0] = String.valueOf(index);
        for (int i1 = 0; i1 < 6; i1++) {
            tempo = tempo.concat(String.format("%02X", packet.getUByte(i1)));
            tempo = tempo.concat(" ");
        }
        data_table[1] = tempo;
        tempo = "";
        for (int i2 = 6; i2 < 12; i2++) {
            tempo = tempo.concat(String.format("%02X", packet.getUByte(i2)));
            tempo = tempo.concat(" ");
        }
        data_table[2] = tempo;

        String tempo_1;
        int tipo = (packet.getUByte(12) * 256) + (packet.getUByte(13));
        if (String.valueOf(packet.getUByte(12)).length() == 1) {
            tempo_1 = '0' + String.valueOf(packet.getUByte(12));
        } else {
            tempo_1 = Integer.toHexString(packet.getUByte(12));
        }
        if (String.valueOf(packet.getUByte(13)).length() == 1) {
            tempo_1 = '0' + String.valueOf(packet.getUByte(13));
        } else {
            tempo_1 = Integer.toHexString(packet.getUByte(13));
        }
        if (tipo > 1500) {
            data_table[3] = "Ethernet";
            ethernet++;
        } else {
            Ethernet eth = new Ethernet();
            if (packet.hasHeader(eth)){
            }
            data_table[3] = "IEEE";
            ieee++;
        }
        
        data_table[4] = String.valueOf(packet.size()) + " bytes";
        System.out.println("#: "+data_table[0]+ "Destino: "+data_table[1]+"Origen: "+data_table[2]+"Protocolo: "+data_table[3]+"longitud: "+data_table[4]);
        mensaje += "Numero de trama: "+data_table[0]+ "\nDestino: "+data_table[1]+"\nOrigen: "+data_table[2]+"\nProtocolo: "+data_table[3]+"\nLongitud: "+data_table[4];
        mensaje += "\n-----------------\n   ";
        jButtonGraficar.setVisible(true);
        this.jTextAreaInfo.setText(mensaje);
        index++;
    }
    private Boolean existe(String device){
       for(int j=0; j<jComboBoxInterfaz.getItemCount(); j++){
           if(jComboBoxInterfaz.getItemAt(j).equals(device))
               return true;
       }
       return false;
    }
    private void jButtonAbrirActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonAbrirActionPerformed
        abrirArchivo();
    }//GEN-LAST:event_jButtonAbrirActionPerformed

    private void jComboBoxInterfazActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBoxInterfazActionPerformed
        jScrollPane1.setVisible(true);
        int index = jComboBoxInterfaz.getSelectedIndex();
        System.out.println(index);
        try{
            device = alldevs.get(index-1); // We know we have at least 1 device
        }catch(Exception e){
            System.out.println("ERROR");
        }
        System.out.printf("\nChoosing '%s' on your behalf:\n", (device.getDescription() != null) ? device.getDescription() : device.getName());
        String info;
        info = "Interfaz: " + device.getDescription();
        try {
            info += "\nMAC: "+ asString(device.getHardwareAddress());
        } catch (IOException ex) {
            Logger.getLogger(Interfaz.class.getName()).log(Level.SEVERE, null, ex);
        }
        List<PcapAddr> direcciones = device.getAddresses();
        for(PcapAddr direccion:direcciones){
            System.out.println(direccion.getAddr().toString());
            info += "\n"+direccion.getAddr().toString();
        }//foreach
        jTextAreaInfoDevice.setText(info);
        jButtonEmpezar.setVisible(true);
        jButtonPausar.setVisible(true);
        jButtonPausar.setEnabled(false);
        jButtonEmpezar.setEnabled(true);
        jButtonGuardar.setEnabled(false);
        jButtonInfo.setEnabled(false);
    }//GEN-LAST:event_jComboBoxInterfazActionPerformed

    private void jButtonPausarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonPausarActionPerformed
        jButtonPausar.setEnabled(false);
        jButtonEmpezar.setEnabled(true);
        jButtonGuardar.setEnabled(true);
        jButtonInfo.setEnabled(true);
        pcap.breakloop();
        System.out.println("Ethernet" + ethernet);
        System.out.println("IEEE" + ieee);
   
        System.out.println("Ethernet:"+getEthernet());
         System.out.println("IEEE:"+getIeee());
         setEthernet(ethernet);
       
    }//GEN-LAST:event_jButtonPausarActionPerformed

    private void jButtonEmpezarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonEmpezarActionPerformed
        jButtonPausar.setEnabled(true);
        jButtonEmpezar.setEnabled(false);
        jButtonGuardar.setEnabled(false);
        jButtonInfo.setEnabled(false);
        final SwingWorker worker = new SwingWorker() {
                @Override
                protected Object doInBackground() throws Exception {
                    capturaReal();
                    return null;
                }
            };
            worker.execute();
    }//GEN-LAST:event_jButtonEmpezarActionPerformed
    
    public int getEthernet() {
        return ethernet;
    }

    public void setEthernet(int ethernet) {
        this.ethernet = ethernet;
    }

    public int getIeee() {
        return ieee;
    }

    public void setIeee(int ieee) {
        this.ieee = ieee;
    }
    
    private void ini(){
        index = 0;
        jTextAreaInfo.setText("");
        tramas.clear();
    }
    
    private void capturaReal(){
        packetsOnline = new PcapPacketArrayList();
        index = 0;
        ini();
        System.out.println(device.getDescription());
        
       pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }

        /**
         * *************************************************************************
         * Third we create a packet handler which will receive packets from the
         * libpcap loop.
         * ************************************************************************
         */
       PcapPacketHandler<String> jpacketHandler = (PcapPacket packet, String user) -> {
            System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                    new Date(packet.getCaptureHeader().timestampInMillis()),
                    packet.getCaptureHeader().caplen(), // Length actually captured
                    packet.getCaptureHeader().wirelen(), // Original length
                    user // User supplied object
            );

            packetsOnline.add(packet);
            llenar(packet);
        };
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "jNetPcap rocks!");
        
        String format = ".pcap";
        String path = "tmp-capture-file" + format;

        String outputfile = path;
        PcapDumper dumper = pcap.dumpOpen(outputfile); // output file  

        JBufferHandler<PcapDumper> dumpHandler = (PcapHeader header, JBuffer buffer, PcapDumper dumper1) -> {
            dumper1.dump(header, buffer);
        };

        pcap.loop(index, dumpHandler, dumper);
        file = new File(outputfile);
        dumper.close(); // Won't be able to delete without explicit close    
        pcap.close();
    }
    
    private void jButtonInfoActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonInfoActionPerformed
        Info jFrame = new Info(tramas);
        jFrame.setVisible(true);
    }//GEN-LAST:event_jButtonInfoActionPerformed

    private void jButtonGuardarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonGuardarActionPerformed
        JFileChooser fileChooser = new JFileChooser("C:\\Desktop\\Redes");
       
        FileNameExtensionFilter filtroPcap = new FileNameExtensionFilter("*.PCAP", "pcap", ".pcap");
         fileChooser.setFileFilter(filtroPcap);
        if (fileChooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File savefile = fileChooser.getSelectedFile();
            file.renameTo(savefile);
        }
    }//GEN-LAST:event_jButtonGuardarActionPerformed

    private void jButtonLimpiarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonLimpiarActionPerformed
        jTextAreaInfo.setText("");
        
    }//GEN-LAST:event_jButtonLimpiarActionPerformed

    private void jButtonGraficarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonGraficarActionPerformed

    }//GEN-LAST:event_jButtonGraficarActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Interfaz.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Interfaz.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Interfaz.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Interfaz.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Interfaz().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButton1;
    private javax.swing.JButton jButtonAbrir;
    private javax.swing.JButton jButtonEmpezar;
    private javax.swing.JButton jButtonGraficar;
    private javax.swing.JButton jButtonGuardar;
    private javax.swing.JButton jButtonInfo;
    private javax.swing.JButton jButtonLimpiar;
    private javax.swing.JButton jButtonPausar;
    private javax.swing.JComboBox<String> jComboBoxInterfaz;
    private javax.swing.JComboBox<String> jComboBoxTipoCaptura;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabelEdo;
    private javax.swing.JLabel jLabelInterfaz;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTextArea jTextAreaInfo;
    private javax.swing.JTextArea jTextAreaInfoDevice;
    // End of variables declaration//GEN-END:variables
}
