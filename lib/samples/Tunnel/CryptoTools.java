/* Author : Romain Pignard */

import java.io.IOException;
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
	
	
	public static SecretKey extractKey(byte[] received_data, short blockSize, short keyLength, byte[] Rcl) throws IOException
	{
		// suppression du padding
		byte[] unpadded = ArrayTools.unpad(received_data,blockSize);
		
		boolean verif = true;
		// test si le retour contient le nonce envoyé
		for (int i = 0; i < Rcl.length; i++) 
		{
			verif = verif & (unpadded[unpadded.length - Rcl.length - AES_BLOCK_LENGTH + i] == Rcl[i]);				
		}
		
		if(verif)
		{
			//System.out.println("réussite");
			// copie de la valeur de la nouvelle cle 
			byte[] cle = new byte[keyLength];
			
			
			System.arraycopy(unpadded, 0, cle, 0, keyLength);
			
			ArrayTools.printHex(cle);
			System.out.println();
			
			
			return new SecretKeySpec(cle, "AES");
			 	 
		}	
		System.out.println("échec");
		return null;		
	}
	
	
	
	
	public static SecretKey EstablishSessionKey(CardChannel channel, Cipher c_tunnel_encrypt, SecretKey shared_key) throws CardException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
	{
		// generation of the nonce
		short Rcl_lg = 16;
		byte[] Rcl = ArrayTools.RandomArray((short) Rcl_lg);
		
		
		
		
		// command to establish the tunnel			
		ResponseAPDU r = channel.transmit(new CommandAPDU((byte)0xB0, 0x02, 0, 0, Rcl));		
		SecretKey tunnel_key = null;
		
		// response code from the card
		if (r.getSW() != 0x9000) {
			System.out.println("Here : Status word different from 0x9000 "  + r.getSW());
		} 						
		
		
		byte[] received_iv = new byte[16];
		byte[] data = new byte[64];
		System.arraycopy(r.getData(), 0, received_iv, 0, 16);
		System.arraycopy(r.getData(), 16, data, 0, 64);
		
		Cipher c_exchange = Cipher.getInstance("AES/CBC/NoPadding");	        
        c_exchange.init(Cipher.DECRYPT_MODE, shared_key, new IvParameterSpec(received_iv));					
        byte[] data2;
		data2 =  c_exchange.doFinal(data);
		
		
		// Extraction of the session key
		// Upon success, the card is authenticated
		
		tunnel_key = CryptoTools.extractKey(data2, AES_BLOCK_LENGTH, AES_BLOCK_LENGTH, Rcl);		
		if (tunnel_key == null)
		{System.out.println("faaaail");}
		byte[] Rc_received = ArrayTools.ExtractFirstBytes(data2, (short) (2*AES_BLOCK_LENGTH));
		
		
		
		// Authentication of the client to the card
		
		c_tunnel_encrypt = Cipher.getInstance("AES/CBC/NoPadding");			
		
		byte[] secret_padded = ArrayTools.pad(Rc_received,AES_BLOCK_LENGTH);
		byte[] iv_sent = ArrayTools.RandomArray(IV_LENGTH);
		
		
		
		// Init of the ciper object with the parameters
		c_tunnel_encrypt.init(Cipher.ENCRYPT_MODE, tunnel_key, new IvParameterSpec(iv_sent));
		
		// Encryption of the secret
		byte[] encrypted_secret = c_tunnel_encrypt.doFinal(secret_padded);
		byte[] pdu = ArrayTools.concat(iv_sent,encrypted_secret) ;
		
		// Sending to the card		
		r = channel.transmit(new CommandAPDU((byte)0xB0, 0x04, encrypted_secret.length , 0,pdu ));
		if (r.getSW() != 0x9000) {
			System.out.println("Error ici : status word different from 0x9000 "  + r.getSW());
			return null;
		} else {
			// the card has authenticated the client
		}
			
		return tunnel_key;
	}
	
	public static void CreateTunnel(Cipher encrypt, Cipher decrypt, CardChannel channel,SecretKey shared_key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CardException, IOException
	{
		SecretKey k = EstablishSessionKey(channel,encrypt,shared_key);		
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
