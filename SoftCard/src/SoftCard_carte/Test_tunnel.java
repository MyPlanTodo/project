/* Author : Romain Pignard */

import java.util.List;

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

public class Test_tunnel {
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
				
				int choix = new Integer(args[0]);
			    int	compteur = 0;
			       switch (choix) {
			      
			
			       case 1 : 
			    	   while(compteur < new Integer(args[1]))
			    	   {
			    		   compteur++;
			    		   new Tunnel(shared_key);
			    	   }
			    	   
			    	   break;
			
			       		
				    case 2 : 	
				    	
				    	Tunnel t = new Tunnel(shared_key);
				    	//t.erase();
				    	while(compteur < new Integer(args[1]))
				    	{
				    		
				    		compteur++;
				    		byte[] PIN = new byte[]{15,12,15,78,95,12,15,78,95,12,15,78,95,12,15,78,95,12,15,78,95,12,15,78,95,12,15,78,95,12,15,78,95,12,15,78,95,12,15,78,95,12,95,12,15,78,95,12,15,78,95};	
				    		//byte[] ran = ArrayTools.RandomArray((short) 10);
				    		System.out.println(PIN.length);
				    		PIN = ArrayTools.concat(PIN, PIN);
				    		t.erase();
				    		t.request((short)2, (short)0,(byte)0,(byte)0,PIN); 		
				    		t.execute();
				    		byte[] res = t.getResponse();
				    		ArrayTools.printByteArray(res);
				    		System.out.println(res.length);
				    		
				    		
				    	}
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
