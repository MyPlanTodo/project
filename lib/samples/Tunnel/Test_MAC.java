/* Author : Romain Pignard */

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.List;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class Test_MAC {
	/* Constantes */
	public static final byte CLA_MONAPPLET = (byte) 0xB0;

	private  final static SecretKey shared_key = new SecretKeySpec(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6}, "AES");

	public static byte[] APPLET_AID= { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x09};

	public static void main(String[] args) throws Exception {
		ResponseAPDU r;
		// byte[] crypted =  testCode();

		/* Connexion au lecteur */
		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terminals;
		try {
			terminals = factory.terminals().list();

			/*	System.out.println("Terminaux : "+terminals);*/

			CardTerminal terminal = terminals.get(0);

			/* Connexion à la carte */
			Card card = terminal.connect("T=1");
			/*	System.out.println("Carte : "+card);*/

			CardChannel channel = card.getBasicChannel();

			/* Sélection de l'applet */
			r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, APPLET_AID));
			if (r.getSW() != 0x9000) {
				System.out.println("Erreur lors de la sélection de l'applet");
				System.exit(1);
			}

			/* Menu principal */

			//while (!fin) 
			{


				long	compteur = 0;
				Tunnel t = new Tunnel(shared_key, channel);

				int erreur = 0;

				
				float  num;	
				while(compteur < 1)
				{
					compteur++;			    		  
					//t.erase();					    

					/*BufferedWriter out = new BufferedWriter(new FileWriter("/home/administrateur/cle"));
					out.write("openssl enc -d -aes-128-cbc -K ");
					out.close();*/
					
					byte[] PIN = new byte[]{15,12};	
					
					//byte[] ran = ArrayTools.RandomArray((short) 10);
						

					t.erase();
					t.request((short)1, (short)0,(byte)60,(byte)0); 		
					t.execute();
					//float pourcentage = new Float(args[0]);
					/*Random rng = new Random();
					num =  rng.nextFloat();	*/				    		
					t.getDataMAC();
					








				}





			}

			/* Mise hors tension de la carte */
			card.disconnect(false);

		} catch (CardException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}



	}
}
