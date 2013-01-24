

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

public class client_PIN {
	/* Constantes */
	public static final byte CLA_MONAPPLET = (byte) 0xB0;

	public static final byte INS_VERIF_PIN = 0x00;
	public static final byte INS_REMAINING_TRIES = 0x01;
	public static final byte INS_RESET_PIN = 0x02;

	public static byte[] APPLET_AID= { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x00 };

	public static void main(String[] args) {
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
				System.out.println();
				System.out.println("1 - Interroger le compteur");
				System.out.println("2 - Inrementer le compteur");
				System.out.println("3 - Decrementer le compteur");
				
				System.out.println("4 - Quitter");
				System.out.println();
				System.out.println("Votre choix ?");

				int choix = System.in.read();
				while (!(choix >= '1' && choix <= '4')) {
					choix = System.in.read();
				}

				switch (choix) {
				case '1':
					r = channel.transmit(new CommandAPDU((byte)0xB0, INS_REMAINING_TRIES, (byte)0x00, (byte)0x00, 1));

					if (r.getSW() != 0x9000) {
						System.out.println("Erreur : status word different de 0x9000");
					} else {
						System.out.println("Valeur du compteur : " + r.getData()[0]);
					}
					break;

				case '2':
					r = channel.transmit(new CommandAPDU((byte)0xB0, INS_RESET_PIN, (byte)0x00, (byte)0x00));

					if (r.getSW() != 0x9000) {
						System.out.println("Erreur : status word different de 0x9000");
					} else {
						System.out.println("OK");
					}
					break;

				

				case '3':
					byte[] donnees = new byte[2];
					Scanner in = new Scanner(System.in); 
					int PIN = in.nextInt();
					donnees[0] =  (byte) (PIN/256);
					donnees[1] = (byte) (PIN % 256);
					r = channel.transmit(new CommandAPDU((byte)0xB0, INS_VERIF_PIN, (byte)0x02, (byte)0x00, donnees));

					if (r.getSW() != 0x9000) {
						System.out.println("Erreur : status word different de 0x9000");
					} else {
						if(r.getData()[0] != 0)
						{System.out.println("echec");}
						else{System.out.println("reussite");}
						
					}
					break;

				case '4':
					fin = true;
					break;
				}
			}

			/* Mise hors tension de la carte */
			card.disconnect(false);

		} catch (CardException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
