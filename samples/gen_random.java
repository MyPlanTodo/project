/* 
 * Génération de nombres un peu aléatoires par le simulateur.
 * Utilisation du générateur sur
 * L'APDU générique pour générer 0xN octets est
 * 0xb0 0x00 0xN 0x00 0x00 0x00;  
 * On peut récuperer au maximum 127 octets (1016 bits)
 *  INS vaut 0x00 et P1 vaut 0xN
 * 
 * 
 */





package gen_random;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.RandomData;


public class gen_random extends Applet {
	
	public static final byte CLA_MONAPPLET = (byte) 0xB0;
	
	public static final byte INS_NOUVEL_ALEA = 0x00;
	
	
	/* Attributs */
	
	private RandomData rng;
	private short lg;
	
	
	
	

	private gen_random() {
		//générateur non sur
		// à remplacer par ALG_SECURE_RANDOM sur la carte
		rng =  RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		// longueur de la séquence d'octets désirée
		lg = 0;
		
	}

	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new gen_random().register();
	}

	
	public void process(APDU apdu) throws ISOException {
		//récupération du buffer
		byte[] buffer = apdu.getBuffer();
		
		
		
		if (this.selectingApplet()) return;
		
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {
		
		case INS_NOUVEL_ALEA:
			//récupération du nombre d'octets demandés
			lg = buffer[ISO7816.OFFSET_P1];
			//génération de lg nombres et mise
			rng.generateData(buffer, (short) 0,(short) lg);
			//envoi de 
			apdu.setOutgoingAndSend((short) 0, (short) lg);
			break;
		
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}	

	}

}
