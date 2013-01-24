import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;;

// toot

public class AESExample {
	
	private static final String ALGO = "AES/CBC/PKCS5Padding";
	private static final byte[] keyValue = new byte[] {'T','h','e','B','e', 
		's','t','S','e','c','r','e','t','K','e','y','T','h','e','B','e', 
		's','t','S','e','c','r','e','t','K','e','y'
	};
	
	public static String encrypt(String data, byte[] random, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Key key = generateKey(random);
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
		byte[] encVal = c.doFinal(data.getBytes());
		return Base64.encodeBase64String(encVal);
	}
	
	public static String decrypt(String data, byte[] random, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Key key = generateKey(random);
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
		byte[] decVal = c.doFinal(Base64.decodeBase64(data));
		return new String(decVal);
	}

	private static Key generateKey(byte[] random) {
		Key key = new SecretKeySpec(random, "AES");
		String t = Base64.encodeBase64String(key.getEncoded());
		Key key2 = new SecretKeySpec(Base64.decodeBase64(t), "AES");
		return key2;
	}

	/**
	 * @param args
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidAlgorithmParameterException 
	 */
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		String input = "bazingaabazingaaaaaaabazingaabazingaaa";
		String output = "";
		String verif = "";
		
		SecureRandom sr = new SecureRandom();
		byte[] b = new byte[32];
		byte[] iv = new byte[16];
		
		sr.nextBytes(b);
		sr.nextBytes(iv);
		System.out.println("random key length: " + b.length);
		StringBuffer sb = new StringBuffer();
		for (byte d : b) {
			sb.append(String.format("%02x", d));
		}
		System.out.println(sb.toString());
		System.out.println("----------------");
		System.out.println("random iv length: " + iv.length);
		sb = new StringBuffer();
		for (byte d : iv) {
			sb.append(String.format("%02x", d));
		}
		System.out.println(sb.toString());
		
		output = encrypt(input, b, iv);
		verif = decrypt(output, b, iv);
		System.out.println(input.length());
		System.out.println(output);
		System.out.println(output.length());
		System.out.println(verif.equals(input));
	}

}
