/* Author : Romain Pignard */

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
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






public class Tunnel {	
	
	// encryption and decryption objects
	private static Cipher encrypt;	
	private static Cipher decrypt;
	// CBC-MAC object
	private static Cipher CBC_MAC;
	
	// Channel used for communication
	private static CardChannel c;
	
	// Session key used by the tunnel
	private static SecretKey session_key;
	
	
	public Tunnel(SecretKey shared_key, byte secret, CardChannel channel) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CardException
	{	
		c = channel;		
		
		// Initialization of the crypto objects
		
		encrypt = Cipher.getInstance("AES/CBC/NoPadding");		
		
		decrypt = Cipher.getInstance("AES/CBC/NoPadding");
		
		CBC_MAC = Cipher.getInstance("AES/CBC/NoPadding");
		
		// forcing of the CBC-MAC IV to 0,0,0,0,....0 with, the shared_key
		CBC_MAC.init(Cipher.ENCRYPT_MODE, shared_key, new IvParameterSpec(new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
		
		// Establisment of the session key		
		session_key = CryptoTools.EstablishSessionKey(c,encrypt, secret,shared_key);		
		
		
		byte[] iv_softcard = ArrayTools.RandomArray((short) CryptoTools.IV_LENGTH);			
		
		byte[] iv_smartcard = new byte[CryptoTools.IV_LENGTH];		
		
		encrypt.init(Cipher.ENCRYPT_MODE, session_key, new IvParameterSpec(iv_softcard));		
		
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x05, (byte) 0x00, (byte)0x00, iv_softcard));		
		
		if (r.getSW() != 0x9000) {
			System.out.println("Erreur : status word different de 0x9000 : "+r.getSW());
		} else {
			System.arraycopy(r.getData(), 0, iv_smartcard, 0, CryptoTools.IV_LENGTH);
			decrypt.init(Cipher.DECRYPT_MODE, session_key, new IvParameterSpec(iv_smartcard));
		}
			
	}
	
	public Tunnel(CardChannel channel) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CardException
	{	
		this(new SecretKeySpec(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6}, "AES"), (byte) 42, channel);
				
	}
	
	
	public byte[] sendRaw(byte[] input) throws Exception
	{
		
		byte[] iv = ArrayTools.RandomArray((short) CryptoTools.IV_LENGTH);	
		
		encrypt.init(Cipher.ENCRYPT_MODE, session_key, new IvParameterSpec(iv));
		
		byte[] padded = ArrayTools.pad(input, CryptoTools.AES_BLOCK_LENGTH);		
		
		byte[] to_be_sent = encrypt.doFinal(padded);
		
		byte[] MAC = ArrayTools.ExtractLastBytes(CBC_MAC.doFinal(ArrayTools.concat(iv,to_be_sent)), CryptoTools.MAC_LENGTH);
	
		byte[] payload = ArrayTools.concat(ArrayTools.concat(iv,to_be_sent),MAC);		
		
		
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x06, (byte) 0x00, (byte)0x00, payload));
		
		if (r.getSW() != 0x9000) {
			System.out.println("Status word different from 0x9000 : "+r.getSW());
		}		
		
		if(!check_MAC(r.getData()))
		{
			throw new Exception("échec de la vérification du HMAC");
		}	
		byte[]  IV = ArrayTools.ExtractFirstBytes(r.getData(), CryptoTools.IV_LENGTH);	
		
		
		byte[] msg = ArrayTools.ExtractLastBytes(r.getData(), (short) (r.getData().length - CryptoTools.IV_LENGTH));
		msg = ArrayTools.ExtractFirstBytes(msg, (short) (msg.length - CryptoTools.MAC_LENGTH));
		
		decrypt.init(Cipher.DECRYPT_MODE, session_key, new IvParameterSpec(IV));		
		byte[] unpadded = ArrayTools.unpad(decrypt.doFinal(msg), CryptoTools.AES_BLOCK_LENGTH);
		
		return unpadded;
	}
	
	
	
	public void execute() throws CardException
	{
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x12, (byte) 0x00, (byte)0x00));
		if (r.getSW() != 0x9000) {
			System.out.println("Status word different from 0x9000 : "+r.getSW());
		}
		System.out.println("reeeeeussite");
	}
	
	public byte[] getData() throws IllegalBlockSizeException, BadPaddingException, Exception
	{
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x11, (byte) 0x00, (byte)0x00));
		if (r.getSW() != 0x9000) {
			System.out.println("Status word different from 0x9000 : "+r.getSW());
		}
		
		if(!check_MAC(r.getData()))		
		{
			throw new Exception("échec de la vérification du HMAC");
		}	
	
		byte[]  IV = ArrayTools.ExtractFirstBytes(r.getData(), CryptoTools.IV_LENGTH);	
		
		byte[] msg = ArrayTools.ExtractLastBytes(r.getData(), (short) (r.getData().length - CryptoTools.IV_LENGTH));
		msg = ArrayTools.ExtractFirstBytes(msg, (short) (msg.length - CryptoTools.MAC_LENGTH));
		
		decrypt.init(Cipher.DECRYPT_MODE, session_key, new IvParameterSpec(IV));		
		byte[] unpadded = ArrayTools.unpad(decrypt.doFinal(msg), CryptoTools.AES_BLOCK_LENGTH);
		
		return unpadded;		
	}
	
	public void erase() throws CardException
	{
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x13, (byte) 0x00, (byte)0x00));
		if (r.getSW() != 0x9000) {
			System.out.println("Status word different from 0x9000 : "+r.getSW());
		}
	}
	
	
	public static boolean check_MAC(byte[] raw_message) throws IllegalBlockSizeException, BadPaddingException
	{
		// MAC checking with the built-in CBC-MAC object. 		
		
		// extraction of the MAC for comparison
		byte[] received_MAC = ArrayTools.ExtractLastBytes(raw_message, (short) CryptoTools.MAC_LENGTH);	
		
		// extraction of the IV + message for MAC computation
		byte[] msg = ArrayTools.ExtractFirstBytes(raw_message, (short) (raw_message.length - CryptoTools.MAC_LENGTH));
		
		// MAC computation
		byte[] computed_MAC =  ArrayTools.ExtractLastBytes(CBC_MAC.doFinal(msg), (short) CryptoTools.MAC_LENGTH);
						
		// comparison
		return Arrays.equals(received_MAC, computed_MAC);		
	}
	
	
	public void request(short applet_ID,short INS_ID, short P1, short P2, byte[] data) throws Exception
	{
		// full request 
		byte[] rq = new byte[data.length + 8];	
		
		// copy of the parameters inside the request
		rq[0] = (byte) applet_ID;
		rq[1] = (byte) INS_ID;
		rq[2] = (byte) P1;
		rq[3] = (byte) P2;
		rq[4] = (byte) data.length;
		
		// copy of the payload
		System.arraycopy(data, 0, rq, 5, data.length);
		
		// segmentation of the request
		byte[][] segmented_rq = ArrayTools.split(rq,(short) 64);
		ArrayTools.printByteArray(segmented_rq[0]);	
		for (int i = 0; i < segmented_rq.length; i++) 
		{
			System.out.println("envoi requete");
			sendRaw(segmented_rq[i]);			
		}		
	}
}
