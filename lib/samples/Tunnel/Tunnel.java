import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.sound.midi.Receiver;
import javax.swing.text.IconView;






public class Tunnel {	
	
	private static Cipher encrypt;
	private static Cipher CBC_MAC;
	private static Cipher decrypt;
	private static CardChannel c;
	private static SecretKey session_key;
	
	
	public Tunnel(SecretKey shared_key, byte secret, CardChannel channel) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CardException
	{	
		c = channel;
		
		
		encrypt = Cipher.getInstance("AES/CBC/NoPadding");
		
		
		decrypt = Cipher.getInstance("AES/CBC/NoPadding");
		
		CBC_MAC = Cipher.getInstance("AES/CBC/NoPadding");
		
		CBC_MAC.init(Cipher.ENCRYPT_MODE, shared_key, new IvParameterSpec(new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
		
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
	
	
	public byte[] sendRaw(byte[] input) throws IllegalBlockSizeException, BadPaddingException, CardException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		
		
		byte[] iv = ArrayTools.RandomArray((short) CryptoTools.IV_LENGTH);	
		
		encrypt.init(Cipher.ENCRYPT_MODE, session_key, new IvParameterSpec(iv));
		
		byte[] padded = ArrayTools.pad(input, CryptoTools.AES_BLOCK_LENGTH);		
		
		
		byte[] to_be_sent = encrypt.doFinal(padded);
		
		byte[] MAC = ArrayTools.ExtractLastBytes(CBC_MAC.doFinal(to_be_sent), CryptoTools.MAC_LENGTH);
	
		
		
		byte[] payload = ArrayTools.concat(ArrayTools.concat(iv,to_be_sent),MAC);
		//System.out.println("Message envoyé sur le cable (IV + ciphertext + MAC)");
		//ArrayTools.printByteArray(payload, (short) 8);
		
		
		
		
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x06, (byte) 0x00, (byte)0x00, payload));
		
		if (r.getSW() != 0x9000) {
			System.out.println("Status word different from 0x9000 : "+r.getSW());
		}
		
		//System.out.println("message total chiffré reçu de longueur : " + r.getData().length);
		
		//ArrayTools.printByteArray(r.getData(), (short) 16);
		
		
		if(!check_MAC(r.getData()))
		{System.out.println("échec de la vérification du HMAC");}	
		else{System.out.println("réussite de la vérification du HMAC");}
		System.out.println();
		
		
		
		

		
		byte[]  IV = ArrayTools.ExtractFirstBytes(r.getData(), CryptoTools.IV_LENGTH);	
		
		
		byte[] msg = ArrayTools.ExtractLastBytes(r.getData(), (short) (r.getData().length - CryptoTools.IV_LENGTH));
		msg = ArrayTools.ExtractFirstBytes(msg, (short) (msg.length - CryptoTools.MAC_LENGTH));
		
		
		
		decrypt.init(Cipher.DECRYPT_MODE, session_key, new IvParameterSpec(IV));		
		byte[] unpadded = ArrayTools.unpad(decrypt.doFinal(msg), CryptoTools.AES_BLOCK_LENGTH);
		
		return unpadded;
	}
	
	
	
	public static boolean check_MAC(byte[] raw_message) throws IllegalBlockSizeException, BadPaddingException
	{
		byte[] received_MAC = ArrayTools.ExtractLastBytes(raw_message, (short) CryptoTools.MAC_LENGTH);
		
		byte[] msg = ArrayTools.ExtractLastBytes(raw_message, (short) (raw_message.length - CryptoTools.IV_LENGTH));
		msg = ArrayTools.ExtractFirstBytes(msg, (short) (msg.length - CryptoTools.MAC_LENGTH));
		
		byte[] computed_MAC =  ArrayTools.ExtractLastBytes(CBC_MAC.doFinal(msg), (short) CryptoTools.MAC_LENGTH);
		
		/*System.out.println("HMAC recalculé");
		ArrayTools.printByteArray(computed_MAC,(short) 16);
		System.out.println("HMAC reçu");
		ArrayTools.printByteArray(received_MAC,(short) 16);*/
		
		
		return Arrays.equals(received_MAC, computed_MAC);
		

	
	}
	
	
	public void echoRaw(byte[] data)
	{
		byte[][] output = ArrayTools.split(data, (short) 127);		
		
		
		
		
		
	}
	
	
	
	
	
}
