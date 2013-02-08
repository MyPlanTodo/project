import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;


public class CryptoTools {

	static final short IV_LENGTH = 16;
	static final short AES_BLOCK_LENGTH = 16;
	static final short MAC_LENGTH = 16;
	
	
	public static SecretKey extractKey(byte[] received_data, short blockSize, short keyLength, short secret)
	{
		// suppression du padding
		byte[] unpadded = ArrayTools.unpad(received_data,blockSize);
		
		// test si le retour contient le secret
		if(unpadded[unpadded.length - 1] == secret)
		{
		//	System.out.println("réussite");
			// copie de la valeur de la nouvelle cle 
			byte[] cle = new byte[keyLength];
			
			
			System.arraycopy(unpadded, 0, cle, 0, keyLength);
			
			for(int i= 0; i < cle.length;i++)
			{	
			//System.out.print((short) (cle[i] & 0xFF) + " ");
			}
			//System.out.println();
			return new SecretKeySpec(cle, "AES");
			 	 
		}	
		System.out.println("échec");
		return null;		
	}
	
	
	
	
	public static SecretKey EstablishSessionKey(CardChannel channel, Cipher c_tunnel_encrypt, short secret, SecretKey shared_key) throws CardException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		
		// command to establish the tunnel
		ResponseAPDU r = channel.transmit(new CommandAPDU((byte)0xB0, 0x02, 0, 0));		
		SecretKey tunnel_key = null;
		
		// response code from the card
		if (r.getSW() != 0x9000) {
			System.out.println("Status word different from 0x9000 "  + r.getSW());
		} 						
			
		
		
	
						
		
		
		byte[] received_iv = new byte[16];
		byte[] data = new byte[32];
		
		
		
		System.arraycopy(r.getData(), 0, received_iv, 0, 16);
		System.arraycopy(r.getData(), 16, data, 0, 32);
		
		Cipher c_exchange = Cipher.getInstance("AES/CBC/NoPadding");	        
        c_exchange.init(Cipher.DECRYPT_MODE, shared_key, new IvParameterSpec(received_iv));					
        byte[] data2;
		data2 =  c_exchange.doFinal(data);
	
		for(int i= 0; i < data2.length;i++){
		
					 
		 
		}
		
		
		// Extraction of the session key
		// Upon success, the card is authenticated
		tunnel_key = CryptoTools.extractKey(data2, AES_BLOCK_LENGTH, AES_BLOCK_LENGTH, (short) 42);
		if (tunnel_key == null)
		{System.out.println("faaaail");}
		
		// Authentication of the client to the card
		
		c_tunnel_encrypt = Cipher.getInstance("AES/CBC/NoPadding");			
		
		byte[] secret_padded = ArrayTools.pad(new byte[]{(byte) secret},AES_BLOCK_LENGTH);
		byte[] iv_sent = ArrayTools.RandomArray(IV_LENGTH);
		
		for(int i= 0; i < secret_padded.length;i++){
			
			 
				 
		}
		
		// Init of the ciper object with the parameters
		c_tunnel_encrypt.init(Cipher.ENCRYPT_MODE, tunnel_key, new IvParameterSpec(iv_sent));
		
		// Encryption of the secret
		byte[] encrypted_secret = c_tunnel_encrypt.doFinal(secret_padded);
		byte[] pdu = ArrayTools.concat(iv_sent,encrypted_secret) ;
		
		// Sending to the card		
		r = channel.transmit(new CommandAPDU((byte)0xB0, 0x04, encrypted_secret.length , 0,pdu ));
		if (r.getSW() != 0x9000) {
			System.out.println("Error : status word different from 0x9000 "  + r.getSW());
			return null;
		} else {
			// the card has authenticated the client
		}
			
		return tunnel_key;
	}
	
	public static void CreateTunnel(Cipher encrypt, Cipher decrypt, CardChannel channel,short secret,SecretKey shared_key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CardException
	{
		SecretKey k = EstablishSessionKey(channel,encrypt, secret,shared_key);		
		byte[] iv_softcard = ArrayTools.RandomArray((short) IV_LENGTH);	
		byte[] iv_smartcard = new byte[IV_LENGTH];
		encrypt.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv_softcard));
		//int choix = 10;
		//System.out.println("Valeur du compteur : "+choix);
		ResponseAPDU r = channel.transmit(new CommandAPDU((byte)0xB0, 0x01, (byte) 0x00, (byte)0x00, iv_softcard));
		if (r.getSW() != 0x9000) {
			System.out.println("Erreur : status word different de 0x9000 : "+r.getSW());
		} else {
			System.arraycopy(r.getData(), 0, iv_smartcard, 0, IV_LENGTH);
			decrypt.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv_smartcard));
		}
		
		
		
	}
	
	
	
	
}
