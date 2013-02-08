package store;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.Signature;
import javacardx.crypto.Cipher;



public class tunnel2 extends Applet {
		
	
	// mise en place du tunnel
	private static AESKey shared_key; // clé partagée
	private static Cipher chiff_exchange; // ciffrement de l'échange de clés
	
	// clé de session
	private static  AESKey aesk; // clé AES	
	private static Cipher chiff; // objet faisant du (dé)chiffrement
	private static Cipher chiff_crypt;
	private static Cipher chiff_decrypt;
	
	private static Cipher HMAC;
	
	
	
	private static byte[] padded;	
	private static byte[] padded2;
	private static short[] tab;
	private static byte[] auth_iv;
	private static byte[] iv_crypt;
	private static byte[] iv_decrypt;
	private static byte[] cle;
	public static final byte CLA_MONAPPLET = (byte) 0xB0;
	public static final byte SECRET = 42;
	public static final short AES_BLOCK_LENGTH = 16;
	//public static final byte INS_CRYPT = 0x00;
	public static final byte INS_DECRYPT = 0x01;
	public static final byte INS_SET_TUNNEL = 0x02;
	public static final byte INS_ECHO_PLUS_ONE = 0x03;
	public static final byte INS_VERIF_TUNNEL = 0x04;
	public static final byte INS_GENERATE_IV = 0x05; 
	
	public static final byte IV_LENGTH = 16;
	public static final byte MAC_LENGTH = 16;
	
	private static final byte INS_ECHO_RAW = 0x06;
	private static final byte INS_SELECT_APPLET = 0x07;
	private static final byte VERIF_PIN = 0x01;
	
	
	private tunnel2() {
		
		
		try{
			//mise en place des secrets prépartagés.
			shared_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
			shared_key.setKey(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6},(short) 0);
			chiff_exchange = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			
			
			HMAC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			HMAC.init(shared_key,Cipher.MODE_ENCRYPT, new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},(short) 0,IV_LENGTH);
			
			// mise en place de la clé AES 128 en RAM			
			aesk = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
			// choix du mode AES 128 CBC sans padding 
			chiff = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			
			chiff_crypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			chiff_decrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			
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
		padded = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_RESET);
		padded2 = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_RESET);
		auth_iv = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_RESET);
		// sert de compteur de boucle et pour stocker des longueurs
		tab = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
		iv_crypt = JCSystem.makeTransientByteArray((short) IV_LENGTH, JCSystem.CLEAR_ON_RESET);
		iv_decrypt = JCSystem.makeTransientByteArray((short) IV_LENGTH, JCSystem.CLEAR_ON_RESET);
		cle = JCSystem.makeTransientByteArray((short) (KeyBuilder.LENGTH_AES_128/8), JCSystem.CLEAR_ON_RESET);
	}
	
	private static void decrypt(byte[] buffer)
	{
		// réglage en mode chiffrement avec :
		// la clé, le mode, l'emplacement de l'IV, son offset de début et sa longueur.	
		//aesk.setKey(cle,(short) 0);		
		chiff.init(aesk, Cipher.MODE_DECRYPT,buffer,ISO7816.OFFSET_CDATA, IV_LENGTH);							
			
		// on récupère la longueur
		tab[2] = buffer[ISO7816.OFFSET_P1];
		
		// on fait le déchiffrement avec la longueur spécifiée
		chiff.doFinal(buffer, (short)(ISO7816.OFFSET_CDATA+IV_LENGTH),tab[2] , padded,(short) 0);
		
		
		//brutal unpadding		
		for( tab[0] = (short)0;tab[0]< (short)(tab[2] - padded[(short)(tab[2] - 1)]);tab[0]++)	
		{
			buffer[tab[0]] = padded[tab[0]]; 				
		}
		tab[2] = (short)( tab[2] - padded[(short)(tab[2] - 1)]);	
	}
	
	
	private static void compute_MAC(byte[] buffer)
	{
		
		
		HMAC.doFinal(buffer,(short) IV_LENGTH , tab[2], padded, (short) 0);		
		for(tab[0] = 0;tab[0] < MAC_LENGTH;tab[0]++)
		{
			buffer[(short)( tab[2]+ tab[0] + IV_LENGTH)] = padded[(short)(tab[2] - MAC_LENGTH +  tab[0])];				
		}	
		
		
		
		
	}
	
	
	private static void check_MAC(byte[] buffer)
	{
		// message length (w/o IV or MAC)
		tab[2] = (short ) (buffer[ISO7816.OFFSET_LC] - IV_LENGTH - MAC_LENGTH);
		tab[1] = buffer[ISO7816.OFFSET_LC];
				
		HMAC.doFinal(buffer, (short)(ISO7816.OFFSET_CDATA + IV_LENGTH), tab[2], padded, (short) 0);
		for(tab[0] = 0;tab[0] < MAC_LENGTH;tab[0]++)
		{
			if(buffer[(short)(ISO7816.OFFSET_CDATA + tab[1] - MAC_LENGTH + tab[0])] != padded[(short)(tab[0] + tab[2]- MAC_LENGTH)])
			{
				ISOException.throwIt((short) 0x66);
			}	
		}	
		
	}
	
	
	private static void extract_MAC(byte[] buffer)
	{
		// full message length
		tab[1] = buffer[ISO7816.OFFSET_LC];
		for(tab[0] = 0;tab[0] < MAC_LENGTH;tab[0]++)
		{
			padded[tab[0]] = buffer[(short)(ISO7816.OFFSET_CDATA + tab[1] - MAC_LENGTH + tab[0])];			
		}	
		for(tab[0] = 0;tab[0] < MAC_LENGTH;tab[0]++)
		{
			buffer[tab[0]] = padded[tab[0]]; 			
		}					
		
		
	}
	
	
	
	private static void decrypt_tunnel(byte[] buffer)
	{
				
		chiff_decrypt.init(aesk, Cipher.MODE_DECRYPT, buffer, (short) ISO7816.OFFSET_CDATA, IV_LENGTH);	
		
		// on récupère la longueur sans le MAC
		tab[2] = (short) (buffer[ISO7816.OFFSET_LC] - MAC_LENGTH - IV_LENGTH);
		
		// on fait le déchiffrement avec la longueur spécifiée
		chiff_decrypt.doFinal(buffer, (short) ((short)(ISO7816.OFFSET_CDATA) + IV_LENGTH),tab[2] , padded,(short) 0);
		
		
		
		
		for( tab[0] = (short)0;tab[0]< (short)(tab[2]);tab[0]++)	
		{
			buffer[tab[0]] = padded[tab[0]]; 				
		}
		
		
		tab[3] = tab[2];
		tab[2] = (short)( tab[2] - padded[(short)(tab[2] - 1)]);	
	}
	
	private static void encrypt_tunnel(byte[] buffer, short length)
	{
		// IV generation
		gen_random.genRandom(iv_crypt, IV_LENGTH);
		
		// padding 
		tab[2] = padding.pad(padded, buffer, AES_BLOCK_LENGTH, length, (byte) 0);
		
		
		
		for(tab[0] = (short)0;tab[0]< IV_LENGTH ;tab[0]++)
		{
			buffer[tab[0]] = iv_crypt[tab[0]];			
		}
		
		
		
		// setting of the IV		
		chiff_crypt.init(aesk, Cipher.MODE_ENCRYPT, iv_crypt, (short) 0, IV_LENGTH);
		
		
		// encryption with the IV
		chiff_crypt.doFinal(padded, (short) 0, tab[2], padded2, (short) 0 );
		
		for( tab[0] = (short)0;tab[0]< tab[2] ;tab[0]++)	
		{
			buffer[(short)(tab[0] + IV_LENGTH)] = padded2[tab[0]]; 				
		}
	}
	
	
		
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new tunnel2().register();
	}

	
	public void process(APDU apdu) throws ISOException {

		//récupération du buffer
		byte[] buffer = apdu.getBuffer();
		
		
		
		if (this.selectingApplet()) return;
		
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		switch (buffer[ISO7816.OFFSET_INS]) {				
		case INS_SET_TUNNEL: 
			try{
				
			
			//génération de [IV_échange: clé_tunnel]
			gen_random.genRandom(padded,  (short) (KeyBuilder.LENGTH_AES_128/8));
			
			for( tab[0] = 0;tab[0]<0 + KeyBuilder.LENGTH_AES_128/8;tab[0]++)
			{
				cle[tab[0]] = padded[(short)(tab[0] )]; 
				
			}	
			
			gen_random.genRandom(auth_iv, IV_LENGTH);
			// initialisation du générateur avec les paramètres secrets
			chiff_exchange.init(shared_key, Cipher.MODE_ENCRYPT,auth_iv,(short) 0, IV_LENGTH);	
			// envoi du "secret" pour vérifier le bon chiffrement.
			padded[(short) (KeyBuilder.LENGTH_AES_128/8)] = SECRET;
			
			
			
			tab[3] = (short) (padding.pad(padded2,padded , AES_BLOCK_LENGTH, (short) (( KeyBuilder.LENGTH_AES_128/8) + 1 ), (byte) 0));
			for( tab[0] = 0;tab[0]<IV_LENGTH;tab[0]++)
			{
				buffer[tab[0]] = auth_iv[tab[0]]; 
				
			}
			chiff_exchange.doFinal(padded2, (short)0,
					(short) tab[3],buffer,(short) IV_LENGTH);
			
			apdu.setOutgoingAndSend((short)0,(short) (tab[3]+ IV_LENGTH));			
			
			// réglage de la clé de session			
					
			aesk.setKey(cle,(short) 0);	
			
			}
			catch(CryptoException ce)
			{
				if(ce.getReason() == CryptoException.ILLEGAL_USE)
				{ISOException.throwIt((short) 0x01);}
				else if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
				{ISOException.throwIt((short) 0x02);}
				else if (ce.getReason() == CryptoException.INVALID_INIT)
				{ISOException.throwIt((short) 0x19);}
				else if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
				{ISOException.throwIt((short) 0x04);}
				else if (ce.getReason() == CryptoException.UNINITIALIZED_KEY)
				{ISOException.throwIt((short) 0x05);}
				
			}
			catch(APDUException ae)
			{ISOException.throwIt((short) 0x11);}
							
			break;
			
		case INS_VERIF_TUNNEL:
			try{
			
				decrypt(buffer);
				if(buffer[0] == 42)
				{
					apdu.setOutgoingAndSend((short)0,(short) 0);
				}
				else
				{
					ISOException.throwIt((short) 0x50);
				}	
			
			}			
			catch(CryptoException ce)
			{
				if(ce.getReason() == CryptoException.ILLEGAL_USE)
				{ISOException.throwIt((short) 0x01);}
				else if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
				{ISOException.throwIt((short) 0x02);}
				else if (ce.getReason() == CryptoException.INVALID_INIT)
				{ISOException.throwIt((short) 0x19);}
				else if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
				{ISOException.throwIt((short) 0x04);}
				else if (ce.getReason() == CryptoException.UNINITIALIZED_KEY)
				{ISOException.throwIt((short) 0x05);}
				
			}
			catch(APDUException ae)
			{ISOException.throwIt((short) 0x12);}
			
			break;				
		
		
		
		case INS_GENERATE_IV:
			
			
			for(tab[0] = 0; tab[0]< IV_LENGTH;tab[0]++)
			{
				iv_decrypt[tab[0]] = buffer[(short)(tab[0] + ISO7816.OFFSET_CDATA)];				
				
			}				
			chiff_decrypt.init(aesk, Cipher.MODE_DECRYPT, iv_decrypt, (short) 0, IV_LENGTH);
			gen_random.genRandom(iv_crypt, IV_LENGTH);
			for(tab[0] = 0; tab[0]< IV_LENGTH;tab[0]++)
			{
				buffer[tab[0]] = iv_crypt[tab[0]];				
				
			}
			chiff_crypt.init(aesk, Cipher.MODE_ENCRYPT, iv_crypt, (short) 0, IV_LENGTH);
			
			apdu.setOutgoingAndSend((short)0,(short) IV_LENGTH);			
			break;
		
		case INS_ECHO_RAW:
			try{	
				tab[4] = buffer[ISO7816.OFFSET_LC];				
				check_MAC(buffer);	
				decrypt_tunnel(buffer);					
				encrypt_tunnel(buffer,(short)(tab[2]));
				compute_MAC(buffer);
			apdu.setOutgoingAndSend((short)0,(short) ((short)tab[2]+ IV_LENGTH + MAC_LENGTH));
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
			catch(APDUException ae)
			{ISOException.throwIt((short) 0x62);}
			
			break;
			
		

		case INS_SELECT_APPLET: 
			
		try{		
			decrypt_tunnel(buffer);	
			switch(buffer[0]){
			case VERIF_PIN:
				if(ver_PIN.test_PIN(buffer, (short)1,(short) 2))
				{
					ISOException.throwIt((short) 0x9002);		
					
				}
				else
				{
					ISOException.throwIt((short) 0x9001);
				}	
			
			}			
			break;
			
			
			//encrypt_tunnel(buffer,tab[2]);
			//apdu.setOutgoingAndSend((short)0,(short) tab[2]);
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
			catch(APDUException ae)
			{ISOException.throwIt((short) 0x62);}
			
			break;
			
			
			
		
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}	
		
		// TODO Auto-generated method stub

	}

}
