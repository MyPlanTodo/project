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





		/* Menu principal */

		//while (!fin) 
		{


			long	compteur = 0;
			Tunnel t = new Tunnel(shared_key);

			int erreur = 0;


			float  num;	
			while(compteur < 1)
			{
				compteur++;	
				//Thread.sleep(10000);
				//t.erase();					    

				/*BufferedWriter out = new BufferedWriter(new FileWriter("/home/administrateur/cle"));
					out.write("openssl enc -d -aes-128-cbc -K ");
					out.close();*/

				byte[] PIN = new byte[]{15,12,14,45,45,120,56,84,56,84,64,65};	

				//byte[] ran = ArrayTools.RandomArray((short) 10);


				t.erase();
				t.request((short)3, (short)0,(byte)0,(byte)0, PIN); 		
				t.execute();
				//float pourcentage = new Float(args[0]);
				/*Random rng = new Random();
					num =  rng.nextFloat();	*/
				byte[] res = t.getDataMAC();
				System.out.println(res.length);
				System.out.println();				
				
				t.erase();
				t.request((short)3, (short)1,(byte)0,(byte)0, res); 		
				t.execute();
				byte[] dechiff = t.getDataMAC();
				System.out.println(dechiff.length);
				ArrayTools.printByteArray(dechiff);









			}





		}

		/* Mise hors tension de la carte */

	}



}

