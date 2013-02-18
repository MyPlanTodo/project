/* Author : Romain Pignard */

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Scanner;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class client_RSA {
	/* Constantes */
	public static final byte CLA_MONAPPLET = (byte) 0xB0;

		
	public static byte[] APPLET_AID= { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x03 };
	
	public static void main(String[] args) throws IOException {
	        ResponseAPDU r;

		/* Connexion au lecteur */
		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terminals;
		try {
			terminals = factory.terminals().list();

			System.out.println("Terminaux : "+terminals);

			CardTerminal terminal = terminals.get(0);

			/* Connexion à la carte */
			Card card = terminal.connect("T=1");
			System.out.println("Carte : "+card);

			CardChannel channel = card.getBasicChannel();

			/* Sélection de l'applet */
			r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, APPLET_AID));
			if (r.getSW() != 0x9000) {
				System.out.println("Erreur lors de la sélection de l'applet");
				System.exit(1);
			}

			/* Menu principal */
			boolean fin = false;
			while (!fin) {
				System.out.println();
				System.out.println("Application cliente Javacard");
				System.out.println("----------------------------");	
				System.out.println("Votre choix ?");

				
			
				
				 Scanner in = new Scanner(System.in); 
			       System.out.printf("Enter i Value:  ");
			       int choix = in.nextInt();
			
			

			      // FileWriter fstream = new FileWriter("out.txt");
					//	  BufferedWriter out = new BufferedWriter(fstream);
			     
			     
			    	  
				//int choix = 10;
				//System.out.println("Valeur du compteur : "+choix);
					r = channel.transmit(new CommandAPDU((byte)0xB0, 0x00, (byte) choix, (byte)0x00));

					if (r.getSW() != 0x9000) {
						System.out.println("Erreur : status word different de 0x9000");
					} else {
						//System.out.println("Valeur du compteur : " );
						for(int i =0;i< r.getData().length;i++ )
						{	
							System.out.println("lg = "+ (r.getData()[i] +256) % 256);
						}
						System.out.println("lg = "+ r.getData().length);
					}
				 
					 
				
			       

			}

			/* Mise hors tension de la carte */
			card.disconnect(false);

		} catch (CardException e) {
			e.printStackTrace();
		}
	}
}
