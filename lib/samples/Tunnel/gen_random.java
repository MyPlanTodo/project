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



package store;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.RandomData;


public class gen_random extends Applet {
	
	public static final byte CLA_MONAPPLET = (byte) 0xB0;
	
	public static final byte INS_NOUVEL_ALEA = 0x00;
	
	
	/* Attributs */
	
	private static RandomData rng;
	private short[] lg;
	private static byte[] buf;
	
	
	
	

	private gen_random() {
		//générateur non sur
		// à remplacer par ALG_SECURE_RANDOM sur la carte
		rng =  RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		lg = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
		buf = JCSystem.makeTransientByteArray((short) 96, JCSystem.CLEAR_ON_RESET);
		// longueur de la séquence d'octets désirée
		lg[0] = 0;
		
	}
	
	
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new gen_random().register();
	}
	
	
	public static  void genRandom(byte[] buff , short nb)
	{
		try{
		rng =  RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);	
		rng.generateData(buff,(short) 0,(short) nb);
		}
		catch(CryptoException ce)
		{
			if(ce.getReason() == CryptoException.ILLEGAL_USE)
			{ISOException.throwIt((short) 0x01);}
			else if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
			{ISOException.throwIt((short) 0x02);}
			else if (ce.getReason() == CryptoException.INVALID_INIT)
			{ISOException.throwIt((short) 0x03);}
			else if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
			{ISOException.throwIt((short) 0x04);}
			else if (ce.getReason() == CryptoException.UNINITIALIZED_KEY)
			{ISOException.throwIt((short) 0x05);}
			
		}
	}
	
	public void process(APDU apdu) throws ISOException {
		//récupération du buffer
		byte[] buffer = apdu.getBuffer();
		
		
		
		if (this.selectingApplet()) return;
		
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		/*if (ver_PIN.getState() != (short) 0x9000)
		{ISOException.throwIt(ver_PIN.getState());
		
		return;}*/
		switch (buffer[ISO7816.OFFSET_INS]) {
		
		case INS_NOUVEL_ALEA:
			//récupération du nombre d'octets demandés
			lg[0] = buffer[ISO7816.OFFSET_P1];
			//génération de lg nombres et mise
			rng.generateData(buffer, (short) 0,(short) lg[0]);
			//envoi de 
			apdu.setOutgoingAndSend((short) 0, (short) lg[0]);
			break;
		
		default:
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}	

	}

}
