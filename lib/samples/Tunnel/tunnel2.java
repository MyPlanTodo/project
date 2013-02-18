/* Author : Romain Pignard */

package store;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;



public class tunnel2 extends Applet {
		
	
	// shared key and crypto object	
	// shared key
	private static AESKey shared_key; 	
	// crypto object for the key establishment
	private static Cipher cipher_exchange; 
	
	// session parameters	
	// session key
	private static byte[] raw_session_key;
	private static  AESKey session_key;	
	// encryption and decryption objects
	private static Cipher cipher_crypt;
	private static Cipher cipher_decrypt;
	
	// MAC cipher object (improved CBC-MAC)
	private static Cipher MAC;
	
	
	// temp arrays for encryption/decryption
	private static byte[] padded;	
	private static byte[] padded2;
	
	
	// loop variables, length and indexes
	private static short[] tab;
	
	private static byte[] IV;
	public static final byte CLA_MONAPPLET = (byte) 0xB0;	
	public static final short AES_BLOCK_LENGTH = 16;
	
	
	
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
	private static final byte PUT_DATA = 0x10;
	private static final byte GET_DATA = 0x11;
	private static final byte EXECUTE = 0x12;
	private static final byte ERASE_DATA = 0x13;
	
	
	private tunnel2() {
		
		
		try{
			// shared key initialization
			shared_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
			shared_key.setKey(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6},(short) 0);
			cipher_exchange = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			
			// MAC initialization with the shared key and an all-zero IV
			MAC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			MAC.init(shared_key,Cipher.MODE_ENCRYPT, new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},(short) 0,IV_LENGTH);
			
			// session key memory allocation		
			session_key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
			
			// session crypto objects creation
			cipher_crypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			cipher_decrypt = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
			
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
		
		
		
		// Local variables in RAM		// 
		padded = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
		padded2 = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);		
		tab = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
		IV = JCSystem.makeTransientByteArray((short) IV_LENGTH, JCSystem.CLEAR_ON_RESET);		
		raw_session_key = JCSystem.makeTransientByteArray((short) (KeyBuilder.LENGTH_AES_128/8), JCSystem.CLEAR_ON_RESET);
	}
	
	private static void decrypt(byte[] buffer)
	{
		// crypto object initialization
		
		cipher_decrypt.init(session_key, Cipher.MODE_DECRYPT,buffer,ISO7816.OFFSET_CDATA, IV_LENGTH);							
			
		// we get the length
		tab[2] = buffer[ISO7816.OFFSET_P1];
		
		// decryption with the length
		cipher_decrypt.doFinal(buffer, (short)(ISO7816.OFFSET_CDATA+IV_LENGTH),tab[2] , padded,(short) 0);
		
		
		//brutal unpadding			
		Util.arrayCopy(padded, (short) 0,buffer ,(short)0,(short) (tab[2] - padded[(short)(tab[2] - 1)]));		
		tab[2] = (short)( tab[2] - padded[(short)(tab[2] - 1)]);	
	}
	
	
	private static void compute_MAC(byte[] buffer)
	{
		// copy of the data into padded2 for MAC computation
		Util.arrayCopy(buffer, (short) 0,padded2 ,(short)16,(short) (tab[2] + IV_LENGTH));	
		
		// emptying the first block of the message for MAC computation
		Util.arrayFillNonAtomic(padded2, (short) 0,(short) 16,(byte) 0);
		
		// length insertion at the beginning
		padded2[0] =  (byte) (((short)(tab[2] + IV_LENGTH)) % 256);
		padded2[1] =  (byte) (((short)(tab[2] + IV_LENGTH)) / 256);
				
		
		
		
		// actual MAC computation
		MAC.doFinal(padded2,(short) 0 , (short)(tab[2]+ IV_LENGTH + 16), padded, (short) 0);	
		
		
		// MAC insertion
		Util.arrayCopy(padded, (short) (tab[2] - MAC_LENGTH  + IV_LENGTH + 16),buffer ,(short)(tab[2] + IV_LENGTH),(short) MAC_LENGTH);
			
		
	}
	
	
	private static void check_MAC(byte[] buffer)
	{
		// message length (w/o IV or MAC)
		tab[2] = (short ) (buffer[ISO7816.OFFSET_LC] - IV_LENGTH - MAC_LENGTH);
		
		// whole message length
		tab[1] = buffer[ISO7816.OFFSET_LC];
				
		
		// copy of the original message into padded2 for MAC computation		
		Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA,padded2 ,(short)16,(short) (tab[2] + IV_LENGTH));
	
		// emptying the first block of the message for MAC computation
		Util.arrayFillNonAtomic(padded2, (short)0, (short)16,(byte) 0);
	
				
		// length insertion at the beginning		
		padded2[0] =  (byte) ((short)(tab[2] + IV_LENGTH) % 256);
		padded2[1] =  (byte) ((short)(tab[2] + IV_LENGTH) / 256);
				
		
		
		
		// actual MAC computation
		MAC.doFinal(padded2,(short) 0 , (short)(tab[2]+ IV_LENGTH + 16), padded, (short) 0);
		
		
		
		// MAC comparison
		for(tab[0] = 0;tab[0] < MAC_LENGTH;tab[0]++)
		{
			if(buffer[(short)(ISO7816.OFFSET_CDATA + tab[1] - MAC_LENGTH + tab[0])] != padded[(short)(tab[0] + tab[2]- MAC_LENGTH + IV_LENGTH + 16 )])
			{
				ISOException.throwIt((short) 0x66);
			}	
		}	
		
	}
	
	
	private static void decrypt_tunnel(byte[] buffer)
	{
		
		// decryption object initialization
		cipher_decrypt.init(session_key, Cipher.MODE_DECRYPT, buffer, (short) ISO7816.OFFSET_CDATA, IV_LENGTH);	
		
		
		tab[2] = (short) (buffer[ISO7816.OFFSET_LC] - MAC_LENGTH - IV_LENGTH);
		
		// decryption of the data
		cipher_decrypt.doFinal(buffer, (short) ((short)(ISO7816.OFFSET_CDATA) + IV_LENGTH),tab[2] , padded,(short) 0);
		
		// copy of the decrypted data into the output buffer
		Util.arrayCopy(padded, (short) 0,buffer ,(short)0,(short) tab[2]);
		
		
		
		
		tab[3] = tab[2];
		tab[2] = (short)( tab[2] - padded[(short)(tab[2] - 1)]);	
	}
	
	private static void encrypt_tunnel(byte[] buffer, short length)
	{
		// IV generation
		gen_random.genRandom(IV, IV_LENGTH);
		
		// padding 
		tab[2] = padding.pad(padded, buffer, AES_BLOCK_LENGTH, length, (byte) 0);
		
		
		// copy of the into the buffer 
		Util.arrayCopy(IV, (short) 0,buffer ,(short)0,(short) IV_LENGTH);
		
		
		
		
		// setting of the IV		
		cipher_crypt.init(session_key, Cipher.MODE_ENCRYPT, IV, (short) 0, IV_LENGTH);
		
		
		// encryption with the IV
		cipher_crypt.doFinal(padded, (short) 0, tab[2], padded2, (short) 0 );
		
		
		Util.arrayCopy(padded2, (short) 0,buffer ,(short)IV_LENGTH,(short) tab[2]);	
		
	}
	
	
		
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new tunnel2().register();
	}

	
	public void process(APDU apdu) throws ISOException {

		
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
			
			
			Util.arrayCopy(padded, (short) 0,raw_session_key ,(short)0,(short) (KeyBuilder.LENGTH_AES_128/8));
			
			/*for( tab[0] = 0;tab[0]<0 + KeyBuilder.LENGTH_AES_128/8;tab[0]++)
			{
				cle[tab[0]] = padded[(short)(tab[0] )]; 
				
			}	*/
			
			gen_random.genRandom(IV, IV_LENGTH);
			// initialisation du générateur avec les paramètres secrets
			cipher_exchange.init(shared_key, Cipher.MODE_ENCRYPT,IV,(short) 0, IV_LENGTH);	
			
			
			// envoi du "secret" pour vérifier le bon chiffrement.
			
			// récupération de Rcl 
			Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA,padded ,(short) (KeyBuilder.LENGTH_AES_128/8),AES_BLOCK_LENGTH);
			
			
			/*for( tab[0] = 0;tab[0]< AES_BLOCK_LENGTH;tab[0]++)
			{
				padded[(short)(tab[0] +  (KeyBuilder.LENGTH_AES_128/8))] = buffer[(short)(tab[0] + ISO7816.OFFSET_CDATA)]; 
				
			}*/
			
			gen_random.genRandom(padded2, AES_BLOCK_LENGTH);
			
			Util.arrayCopy(padded2, (short)0,padded ,(short) (KeyBuilder.LENGTH_AES_128/8 + AES_BLOCK_LENGTH),AES_BLOCK_LENGTH);
			
			
			/*for( tab[0] = 0;tab[0]< AES_BLOCK_LENGTH;tab[0]++)
			{
				padded[(short)(tab[0] +  (KeyBuilder.LENGTH_AES_128/8) + AES_BLOCK_LENGTH)] = padded2[(short)(tab[0])]; 				
			}*/
			
			
			
			
			
			tab[3] = (short) (padding.pad(padded2,padded , AES_BLOCK_LENGTH, (short) (( KeyBuilder.LENGTH_AES_128/8) + AES_BLOCK_LENGTH + AES_BLOCK_LENGTH), (byte) 0));
			
			Util.arrayCopy(IV, (short) 0,buffer ,(short) 0,IV_LENGTH);
			
			/*for( tab[0] = 0;tab[0]<IV_LENGTH;tab[0]++)
			{
				buffer[tab[0]] = auth_iv[tab[0]]; 
				
			}*/
			cipher_exchange.doFinal(padded2, (short)0,
					(short) tab[3],buffer,(short) IV_LENGTH);
			
			apdu.setOutgoingAndSend((short)0,(short) (tab[3]+ IV_LENGTH ));			
			
			// réglage de la clé de session			
					
			session_key.setKey(raw_session_key,(short) 0);	
			
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
				for(tab[0] = 0 ; tab[0] < tab[2]; tab[0] ++ )
				{
					if (buffer[tab[0]] != padded2[tab[0]])
					{
						ISOException.throwIt((short) 0x50);
					}	
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
		
		
		
	
		
		case INS_ECHO_RAW:
			try{	
				tab[4] = buffer[ISO7816.OFFSET_LC];				
				check_MAC(buffer);	
				decrypt_tunnel(buffer);	
				datastore.putData(buffer, (short) tab[2]);	
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
			{
				ISOException.throwIt((short) 0x62);
			}			
			break;
			
		
		case PUT_DATA:
			tab[4] = buffer[ISO7816.OFFSET_LC];				
			check_MAC(buffer);	
			decrypt_tunnel(buffer);	
			datastore.putData(buffer, (short) tab[2]);
			
			break;
			
		case EXECUTE:	
			datastore.execute();
			break;
			
		case GET_DATA:			
			tab[2] = (short) (datastore.getRemainingData((short)208));
			if(tab[2] == 0)
			{
				ISOException.throwIt((short) 0x6666);
			}	
			datastore.getData(buffer, tab[2]);				
			encrypt_tunnel(buffer,(short)(tab[2]));
			compute_MAC(buffer);			
			apdu.setOutgoingAndSend((short)0,(short) ((short)tab[2]+ IV_LENGTH + MAC_LENGTH));
			break;	
		case ERASE_DATA:
			datastore.eraseData();
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
