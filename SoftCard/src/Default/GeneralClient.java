//package crypto;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Scanner;



import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.apache.commons.codec.binary.Base64;

public class GeneralClient {
	/* Constantes */
	public static final byte CLA_CIPHER = (byte) 0xB0;

	public static final byte INS_CIPHER = 0x00;
	public static final byte INS_UNCIPHER = 0x01;
	public static final byte INS_GET_EXPONENT = 0x02;
	public static final byte INS_GET_MODULUS = 0x03;

	public static final byte INS_GEN = 0x00;

	private static final byte INS_STORE_LOGIN = 0x00;
	private static final byte INS_STORE_MDP = 0x01;
	private static final byte INS_GET_CRED = 0x03;
	private static final byte INS_VAL_PWD = 0x02;
	public static final byte INS_TEST_AUTH = 0x04;
	public static final byte INS_ASK_AUTH = 0x05;
	

	private static final int INS_PIN = 0x00;
	private static final int INS_PUK = 0x02;
	
	// offset AID values
	private static final short AID_PIN = 0x00; 
	private static final short AID_RNG = 0x01;
	private static final byte AID_CYPHER = 0x03;
	private static final byte AID_SIGN = 0x02;
	private static final byte AID_STORE = 0x04; 
	
	public static String ErrorMsg = "Please type your PIN before using this function";
	private  final static SecretKey shared_key = new SecretKeySpec(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6}, "AES");

	private static String bytesToHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (byte b : bytes) {
			sb.append(String.format("0x%02x ", b));
		}
		return new String(sb);
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		ResponseAPDU r;

		
		try {
			// Secure tunnel establishment
			Tunnel t = new Tunnel(shared_key);


			/* Main menu */
			boolean fin = false;
			byte[] data = null;
			PublicKey publicKey = null;
			byte[] clair = new String("Hello World").getBytes();
			while (!fin) {
				System.out.println();
				System.out.println("Application cliente Javacard");
				System.out.println("----------------------------");
				System.out.println("Certaines fonctions nécessitent que le bon code PIN soit entré");
				System.out.println();
				System.out.println("1 - Récupérer la clef publique de chiffrement");
				System.out.println("2 - Chiffrer un message");
				System.out.println("3 - Déchiffrer un message");
				System.out.println("4 - Aléa");
				System.out.println("5 - Stocker identifiants");
				System.out.println("6 - Valider le mot de passe");
				System.out.println("7 - Récupérer identifiants");
				System.out.println("8 - Check PIN");
				System.out.println("9 - signature");
				System.out.println("10 - vérification");
				System.out.println("11 - Quitter");
				System.out.println();
				System.out.println("Votre choix ?");

				Scanner sc = new Scanner(System.in);
				int choix = sc.nextInt();
				while (!(choix >= 0 && choix <= 11)) {
					choix = System.in.read();
				}

				BigInteger exp = null;
				byte[] result;
				String s = "hello world and this is a test for long long long loglg longlong g llonglong longlong longlong longlong long messages";
				
				switch (choix) {
				case 1:
					// Exponent request
					t.erase();
					t.request((short)AID_CYPHER, INS_GET_EXPONENT, (byte)0x00, (byte)0x00);
					if(t.execute() != 0x9000)
					{
						System.out.println("error");
					}	
					result = t.getResponse();
					exp = new BigInteger(1, result);

					System.out.println(exp.toString());
	
					
					// Modulus request
					t.erase();
					t.request((short)AID_CYPHER,  INS_GET_MODULUS, (byte)0x00, (byte)0x00);
					t.execute();
					result = t.getResponse();
					BigInteger mod = new BigInteger(1, result);

					KeyFactory kf = KeyFactory.getInstance("RSA");
					RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(mod, exp);
					publicKey = kf.generatePublic(pubKeySpec);
					System.out.println(bytesToHexString(publicKey.getEncoded()));
					System.out.println(publicKey.toString());

					break;

				case 2:
					// encryption
					t.erase();
					t.request((short)AID_CYPHER, INS_CIPHER, (byte)0x00, (byte)0x00, s.getBytes());
					t.execute();
					result = t.getResponse();
					System.out.println("Texte : " + s);
					System.out.println("Chiffré : " + Base64.encodeBase64String(result));

					break;

				case 3:
					// decryption
					Cipher c = Cipher.getInstance("RSA");
					byte[] clearText = s.getBytes();
					System.out.println(clearText.length);
					c.init(Cipher.ENCRYPT_MODE, publicKey);
					byte[] ciphered = c.doFinal(clearText);
					System.out.println("Clair : " + new String(clearText));
					System.out.println("Chiffré : " + Base64.encodeBase64String(ciphered));

					t.erase();
					t.request((short)AID_CYPHER, INS_UNCIPHER, (byte) 0x00, (byte)0x00, ciphered);
					t.execute();
					result = t.getResponse();
					System.out.println("Déchiffré " + new String(result));
					
					break;

				case 4:
					// Random number generation
					t.erase();
					Scanner in2 = new Scanner(System.in);
					int nb = in2.nextInt();
					if (nb > 383)					
					{
						t.request((short)AID_RNG, INS_GEN, (byte) (nb-256), (byte)0x02);
					}

					if (nb > 127)					
					{
						t.request((short)AID_RNG, INS_GEN, (byte) (nb-256), (byte)0x01);
					}	
					else{
						t.request((short)AID_RNG, INS_GEN, (byte)  nb, (byte)0x00);
					}

					t.execute();
					result = t.getResponse();
					ArrayTools.printByteArray(result,(short) 10);
					
					                        
					break;

				case 5:
					// ID storage					
					Scanner in3 = new Scanner(System.in);
					System.out.println("Login Password");
					String strStored = in3.nextLine();
					byte[] stored = strStored.getBytes();
					
					int i = 0;
					boolean stop = false;

					while (i < strStored.length() && !stop) {
						if (strStored.charAt(i) == ' ') {
							stop = true;
						}
						else {
							i++;
						}
					}

					if (stop) {
						byte[] login = new byte[i];
						byte[] mdp = new byte[stored.length - i - 1];
						System.arraycopy(stored, 0, login, 0, i);
						System.arraycopy(stored, i + 1, mdp, 0, stored.length - i - 1);

						System.out.println(login.length + "|" + new String(login) + "|");
						System.out.println(mdp.length + "|" + new String(mdp) + "|");
						
						// Store login
						t.erase();
						t.request((short)AID_STORE,(short) INS_STORE_LOGIN,(byte) 0x00,(byte)  0x00, login);
						t.execute();


						// Store mdp
						t.erase();
						t.request((short)AID_STORE,(short) INS_STORE_MDP,(byte) 0x00,(byte)  0x00, mdp);
						t.execute();
						result = t.getResponse();
						System.out.println((result[0] == 1) ? true : false);   
						if ((result.length == 1) && (result[0] == -1))
						{
							System.out.println(ErrorMsg);
						}	
					}
					else {
						throw new Exception("Could not store data");
					}

					break;
				case 6: 
					// ID validation
					t.erase();
					t.request((short) AID_STORE, INS_VAL_PWD,(byte)0 ,(byte) 0);
					t.execute();

					break;

				case 7:
					// Retrieve data
					t.erase();
					t.request((short)AID_STORE,INS_GET_CRED,(byte) 0x00,(byte) 0x00);
					int res =  t.execute();
					System.out.println("recup"+res);

					data = t.getResponse();
					if ((data.length == 1) && (data[0] == -1))
					{
						System.out.println(ErrorMsg);
					}	
					else
					{
						System.out.println(bytesToHexString(data));
						System.out.println("Stocké : " + new String(data));
					}
					
					break;

				case 8:
					// PIN check
					Scanner in = new Scanner(System.in);
					int pin = in.nextInt();

					byte[] data1 = new byte[2];
					data1[0] = (byte)(pin >> 8);
					data1[1] = (byte)(pin & 0xFF);

					
					t.erase();
					t.request((short)AID_PIN,(short) INS_PIN,(byte) 0x02, (byte)0x00, data1);
					t.execute();
					System.out.println("Res : " + bytesToHexString(t.getResponse()));

					break;

				case 9:
					// Signature
					t.erase();
					t.request((short) AID_SIGN, INS_ASK_AUTH, (byte)0x00, (byte)0x00, clair);
					System.out.println("Clair :" + bytesToHexString(clair));

					t.execute();
					byte[] dechiff = t.getResponse();
					System.out.print("Message signé: ");
					System.out.println(bytesToHexString(dechiff));

					break;
					
				case 10:
					// Signature check
					t.erase();
					t.request((short) AID_SIGN,  INS_ASK_AUTH, (byte)0x00, (byte)0x00, clair);
					t.execute();
					
					/* We ask for the signature first */
					System.out.println("Clair :" + bytesToHexString(clair));
					byte[] signed = t.getResponse();

					System.out.print("Message signé: ");
					System.out.println(bytesToHexString(signed));

					/* We send the signature */
					t.erase();
					t.request((short) AID_SIGN, INS_TEST_AUTH, (byte) 0x00, (byte)0x00, signed);
					t.execute();					
					byte[] res2 =  t.getResponse();
					System.out.print("Chiffré renvoyé : ");
					System.out.println(bytesToHexString(res2));

					/* We send the original message  and the card automagically checks if the signature matches */
					t.erase();
					t.request((short) AID_SIGN, INS_TEST_AUTH, (byte) 0x00, (byte)0x01, clair);
					t.execute();
					
					if(t.getResponse()[0] == 1)
					{
						System.out.println("You fail at failing");
					}
					else
					{
						System.out.println("Success");
					}
					
					break;
					
				case 11:
					// end
					fin = true;
					break;
				}
			}

		} catch (CardException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
