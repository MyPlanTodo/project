import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;


import org.apache.commons.codec.binary.Base64;


public class RSAExample {
	
	private Key pubKey;
	private Key privKey;
	private SecureRandom random;
	
	public RSAExample() throws NoSuchAlgorithmException, NoSuchProviderException {
		this.random = new SecureRandom();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		
		generator.initialize(1024, this.random);
		KeyPair pair = generator.generateKeyPair();
		this.pubKey = pair.getPublic();
		this.privKey = pair.getPrivate();
	}
	
	public String encrypt(String input) throws Exception {
		Cipher c = Cipher.getInstance("RSA");
		
		c.init(Cipher.ENCRYPT_MODE, this.pubKey, this.random);
		byte[] cipherText = c.doFinal(input.getBytes());
		return Base64.encodeBase64String(cipherText);
	}
	
	public String decrypt(String input) throws Exception {
		Cipher c = Cipher.getInstance("RSA");
		
		c.init(Cipher.DECRYPT_MODE, this.privKey);
		byte[] cipherText = c.doFinal(Base64.decodeBase64(input.getBytes()));
		return new String(cipherText);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException {
		RSAExample t = null;
		try {
			t = new RSAExample();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String test = "";
		String res = "";
		try {
			test = t.encrypt("bazingbazingabazingabazingaabazingbazingabazingabazingaabazingbazingabazingabazingaabazingbazingabazing");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			res = t.decrypt(test);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("cypher: " + test);
		System.out.println("plain: " + res);
		System.out.println(test.length());
		String a = Base64.encodeBase64String(t.pubKey.getEncoded());
		System.out.println(a.length());
		byte[] b = Base64.decodeBase64(a);
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(b));
		System.out.println(publicKey);
		System.out.println(t.pubKey);
		System.out.println("---------------------------");
		/* Empreinte */
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		byte[] hash = md.digest("password".getBytes());
		StringBuffer sb = new StringBuffer();
		for (byte d : hash) {
			sb.append(String.format("%02x", d));
		}
		System.out.println(sb.toString());
	}

}
