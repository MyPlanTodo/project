/* Author : Romain Pignard */

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
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
	
	
	public Tunnel(SecretKey shared_key, CardChannel channel) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CardException, IOException
	{	
		c = channel;		
		
		// Initialization of the crypto objects
		
		encrypt = Cipher.getInstance("AES/CBC/NoPadding");		
		
		decrypt = Cipher.getInstance("AES/CBC/NoPadding");
		
		CBC_MAC = Cipher.getInstance("AES/CBC/NoPadding");
		
		// forcing of the CBC-MAC IV to 0,0,0,0,....0 with, the shared_key
		CBC_MAC.init(Cipher.ENCRYPT_MODE, shared_key, new IvParameterSpec(new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}));
		
		// Establisment of the session key		
		session_key = CryptoTools.EstablishSessionKey(c,encrypt,shared_key);				
	}
	
	public Tunnel(CardChannel channel) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, CardException, IOException
	{	
		this(new SecretKeySpec(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6}, "AES"), channel);
				
	}
	
	
	public void sendRaw(byte[] input) throws Exception
	{
		
		// IV generation
		byte[] iv = ArrayTools.RandomArray((short) CryptoTools.IV_LENGTH);	
		
		// crypto object initialization
		encrypt.init(Cipher.ENCRYPT_MODE, session_key, new IvParameterSpec(iv));
		
		//byte[] padded = ArrayTools.pad(input, FIXED_MSG_LENGTH);	
		
		byte[] padded = ArrayTools.pad(input, CryptoTools.AES_BLOCK_LENGTH);		
		
		byte[] to_be_sent = encrypt.doFinal(padded);		
		
		//ArrayTools.printByteArray(ArrayTools.add_size(ArrayTools.concat(iv,to_be_sent),(short) 16),(short) 16);
		
		
		byte[] MAC = ArrayTools.ExtractLastBytes(CBC_MAC.doFinal(ArrayTools.add_size(ArrayTools.concat(iv,to_be_sent),(short) 16)), CryptoTools.MAC_LENGTH);
	
		byte[] payload = ArrayTools.concat(ArrayTools.concat(iv,to_be_sent),MAC);		
		
		
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x10, (byte) 0x00, (byte)0x00, payload));
		
		if (r.getSW() != 0x9000) {
			System.out.println(" here : Status word different from 0x9000 : "+r.getSW());
		}		
		
	}
	
	
	
	public void execute() throws CardException
	{
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x12, (byte) 0x00, (byte)0x00));
		if (r.getSW() != 0x9000) {
			System.out.println(" here2 : Status word different from 0x9000 : "+r.getSW());
		}
		
	}
	
	
	
	
	
	
	public byte[] getResponse() throws IllegalBlockSizeException, BadPaddingException, Exception
	{
		byte[] response = new byte[]{}; 
		byte[] recu;
		recu = this.getData();	
		
		
		while(recu.length != 0)
		{    		
			
			//System.out.println(recu.length);
			ArrayTools.printByteArray(recu, (short) 10);					    		
    		recu = this.getData();	
		}
		response = ArrayTools.concat(response,recu);
		return response;
		
	}
	
	
	
	
	
	public byte[] getData() throws IllegalBlockSizeException, BadPaddingException, Exception
	{
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x11, (byte) 0x00, (byte)0x00));
		if ((r.getSW() != 0x9000) && (r.getSW() != 0x6666)) {
			System.out.println("Status word different from 0x9000 : "+r.getSW());
		}
		
		if (r.getSW() == 0x6666) {
			return new byte[]{};
		}
		
		// MAC check
		
		if(!check_MAC(r.getData()))		
		{
			throw new Exception("CBC-MAC check failed ");
		}	
	
		// IV extraction
		byte[]  IV = ArrayTools.ExtractFirstBytes(r.getData(), CryptoTools.IV_LENGTH);	
		
		// message extraction		
		// "deletion" of the IV 
		byte[] msg = ArrayTools.ExtractLastBytes(r.getData(), (short) (r.getData().length - CryptoTools.IV_LENGTH));
		// "deletion" of the MAC 
		msg = ArrayTools.ExtractFirstBytes(msg, (short) (msg.length - CryptoTools.MAC_LENGTH));
		
		
		// crypto object initialization
		
		decrypt.init(Cipher.DECRYPT_MODE, session_key, new IvParameterSpec(IV));
		
		

		// message decryption	
		
		byte[] padded = decrypt.doFinal(msg);				
		
		// unpadding
		byte[] unpadded = ArrayTools.unpad(padded, CryptoTools.AES_BLOCK_LENGTH);
		System.out.println();
		System.out.println("unpadded");
		ArrayTools.printHex(unpadded);
		System.out.println();
		return unpadded;	
		
	}
	
	
	public byte[] getDataMAC() throws IllegalBlockSizeException, BadPaddingException, Exception
	{
		ResponseAPDU r = c.transmit(new CommandAPDU((byte)0xB0, 0x11, (byte) 0x00, (byte)0x00));
		if ((r.getSW() != 0x9000) && (r.getSW() != 0x6666)) {
			System.out.println("Status word different from 0x9000 : "+r.getSW());
		}
		
		if (r.getSW() == 0x6666) {
			return new byte[]{};
		}
		
		// MAC check
		
		byte[] data = r.getData();		
		
	
		// IV extraction
		byte[]  IV = ArrayTools.ExtractFirstBytes(r.getData(), CryptoTools.IV_LENGTH);	
		
		// message extraction		
		// "deletion" of the IV 
		byte[] msg = ArrayTools.ExtractLastBytes(r.getData(), (short) (r.getData().length - CryptoTools.IV_LENGTH));
		// "deletion" of the MAC 
		msg = ArrayTools.ExtractFirstBytes(msg, (short) (msg.length - CryptoTools.MAC_LENGTH));
		
		
		System.out.print("openssl enc -d -AES-128-CBC -iv ");
		
		
		ArrayTools.printHex(IV);
		
		
		System.out.print(" -K ");
		
		ArrayTools.printHex((session_key.getEncoded()));
		
		System.out.print(" -out decode");
		System.out.println();
		// crypto object initialization
		
		
		
		OutputStream os = new FileOutputStream("/home/administrateur/msg");
		os.write(msg);
	
		
		
		// crypto object initialization
		decrypt.init(Cipher.DECRYPT_MODE, session_key, new IvParameterSpec(IV));
		
		// message decryption	
		byte[] padded = decrypt.doFinal(msg);				
		
		// unpadding
		byte[] unpadded = ArrayTools.unpad(padded, CryptoTools.AES_BLOCK_LENGTH);
		
		
		System.out.println();
		System.out.println("unpadded");
		ArrayTools.printHex(unpadded);
		
		
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
		// the add_size function adds a block with the payload size at the beginning to obtain a secure CBC-MAC.
		
		byte[] size_n_msg = ArrayTools.add_size(ArrayTools.ExtractFirstBytes(raw_message, (short) (raw_message.length - CryptoTools.MAC_LENGTH)),(short) 16);
		
		
		
		// MAC computation
		byte[] computed_MAC =  ArrayTools.ExtractLastBytes(CBC_MAC.doFinal(size_n_msg), (short) CryptoTools.MAC_LENGTH);
						
		// comparison
		return Arrays.equals(received_MAC, computed_MAC);		
	}
	
	
	public void request(short applet_ID,short INS_ID, byte P1, byte P2, byte[] data) throws Exception
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
		//ArrayTools.printByteArray(segmented_rq[0]);	
		for (int i = 0; i < segmented_rq.length; i++) 
		{
			// sending of the fragmented request
			// it will erassembled on the other side
			sendRaw(segmented_rq[i]);			
		}		
	}
	public void request(short applet_ID,short INS_ID, byte P1, byte P2) throws Exception
	{
		// request without data
		request(applet_ID,INS_ID,P1,P2, new byte[]{} );
	}
}
