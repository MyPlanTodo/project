/* Author : Romain Pignard */

package store;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;


public class crypto_applet extends Applet {
		
	
	private static  AESKey aesk; // clé AES
	private Cipher chiff; // objet faisant du (dé)chiffrement
	
	private static byte[] padded;	
	private static short[] tab;
	public static final byte CLA_MONAPPLET = (byte) 0xB0;
	public static final byte INS_CRYPT = 0x00;
	public static final byte INS_DECRYPT = 0x01;
	public static final byte IV_LENGTH = 16;
	
	
	private crypto_applet() {
		
		
		try{
			// mise en place de la clé AES 128 en RAM		
			aesk = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
			// choix du mode AES 128 CBC sans padding 
			chiff = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
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
		
		
		
		// variables locales en RAM.
		// sert à stocker les octets après chiffrement/déchiffrement
		padded = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_RESET);
		// sert de compteur de boucle et pour stocker des longueurs
		tab = JCSystem.makeTransientShortArray((short) 96, JCSystem.CLEAR_ON_RESET);
	}

	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new crypto_applet().register();
	}

	
	public void process(APDU apdu) throws ISOException {

		//récupération du buffer
		byte[] buffer = apdu.getBuffer();
		
		// affectation de la valeur de la clé
		aesk.setKey(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6},(short) 0);
		
		if (this.selectingApplet()) return;
		
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		switch (buffer[ISO7816.OFFSET_INS]) {
		
		case INS_CRYPT:
			try{	
			// réglage en mode chiffrement avec :
			// la clé, le mode, l'emplacement de l'IV, son offset de début et sa longueur.	
			chiff.init(aesk, Cipher.MODE_ENCRYPT,buffer,ISO7816.OFFSET_CDATA, IV_LENGTH);
			
			chiff.doFinal(buffer, (short)(ISO7816.OFFSET_CDATA+IV_LENGTH),(short) 16, padded,(short) 0);	
			}		
			catch(CryptoException ce)
			{
				if(ce.getReason() == CryptoException.ILLEGAL_USE)
				{ISOException.throwIt((short) 0x10);}
				else if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
				{ISOException.throwIt((short) 0x11);}
				else if (ce.getReason() == CryptoException.INVALID_INIT)
				{ISOException.throwIt((short) 0x12);}
				else if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
				{ISOException.throwIt((short) 0x13);}
				else if (ce.getReason() == CryptoException.UNINITIALIZED_KEY)
				{ISOException.throwIt((short) 0x14);}
				
			}
			for( tab[0] = (short)0;tab[0]<(short) 16;tab[0]++)
			{
				buffer[tab[0]] = padded[tab[0]]; 
				
			}
			
			
			apdu.setOutgoingAndSend((short)0,(short)16);
			//apdu.setOutgoingAndSend((short) 0, (short) pub_key.getExponent(buffer, (short) 0));
			
			
			break;
		case INS_DECRYPT:
			try{
			// réglage en mode chiffrement avec :
			// la clé, le mode, l'emplacement de l'IV, son offset de début et sa longueur.	
			chiff.init(aesk, Cipher.MODE_DECRYPT,buffer,ISO7816.OFFSET_CDATA, IV_LENGTH);
							
			}		
			catch(CryptoException ce)
			{
				if(ce.getReason() == CryptoException.ILLEGAL_USE)
				{ISOException.throwIt((short) 0x16);}
				else if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
				{ISOException.throwIt((short) 0x17);}
				else if (ce.getReason() == CryptoException.INVALID_INIT)
				{ISOException.throwIt((short) 0x18);}
				else if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
				{ISOException.throwIt((short) 0x19);}
				else if (ce.getReason() == CryptoException.UNINITIALIZED_KEY)
				{ISOException.throwIt((short) 0x21);}
				
			}
			tab[2] = buffer[ISO7816.OFFSET_P1];
			chiff.doFinal(buffer, (short)(ISO7816.OFFSET_CDATA+IV_LENGTH),tab[2] , padded,(short) 0);
			for( tab[0] = (short)0;tab[0]< tab[2] ;tab[0]++)
			{
				buffer[tab[0]] = padded[tab[0]]; 
				
			}
			
			
			apdu.setOutgoingAndSend((short)0,tab[2]);
			//apdu.setOutgoingAndSend((short) 0, (short) pub_key.getExponent(buffer, (short) 0));
			
			
			break;	
		
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}	

	
		
		
		
		// TODO Auto-generated method stub

	}

}
