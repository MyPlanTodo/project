// TODO : créer classe d'exception personelle

//package Default;

import java.io.Console;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * This class allow user to send requests to the smartcard :
 * cipher, uncipher, get the public key, sign data or verify it
 * @author Emmanuel Mocquet (for most of it)
 * @author Romain Pignard (for tunnel adaptation)
 * @version 1.1
 */
public class SoftCard {
	
	private  final static SecretKey shared_key = new SecretKeySpec(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6}, "AES");
	public static final byte CLA_SMARTCARD = (byte) 0xB0;

	// Constants identifying each applet on the smartcard
//	public static byte[] GEN_RANDOM_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01 };
//	public static byte[] SIGN_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x02 };
//	public static byte[] STORE_ID_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x03 };
//	public static byte[] CIPHER_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x04 };
//	public static byte[] PIN_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x08 };
//	public static byte[] TUNNEL_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x09 };

	
	public static byte AID_PIN = 0x00;
	public static byte AID_RANDOM = 0x01;
	public static byte AID_SIGN = 0x02;
	public static byte AID_CYPHER = 0x03;
	public static byte AID_STORE = 0x04;

	// Constants associated with the generation of random number's applet
	public static final byte INS_GEN = 0x00;

	// Default size of the generated password
	private static final byte SIZE_PWD = 0x64;

	// Constants for verification and signature of data with the associated applet
	private static final byte INS_SIGN = 0x04;
	private static final byte INS_VERIF = 0x05;

	// Constants associated with the ciphering applet
	private static final byte INS_CIPHER = 0x00;
	private static final byte INS_UNCIPHER = 0x01;
	private static final byte INS_GET_EXPONENT = 0x02;
	private static final byte INS_GET_MODULUS = 0x03;

	// Constants associated with the applet handling the PIN code
	private static final byte INS_VERIF_PIN = 0x00;                              
	private static final byte INS_PIN_REMAINING_TRIES = 0x01;                        
	private static final byte INS_PUK_REMAINING_TRIES = 0x02;                        
	private static final byte INS_UNLOCK_WITH_PUK = 0x03;
	private static final byte INS_GET_PIN = 0x04;
	private static final byte INS_GET_PUK = 0x05;
	private static final byte INS_IS_LOCKED = 0x06;

	private static final byte SIZE_PIN = 0x02;
	private static final byte SIZE_PUK = 0x02;

	// Constants associated with the applet storing user's credentials
	private static final byte INS_STORE_LOGIN = 0x00;
	private static final byte INS_STORE_PWD = 0x01;
	private static final byte INS_VALIDATE_PWD = 0x02;
	private static final byte INS_GET_CRED = 0x03;

	private TerminalFactory factory;
	private static List<CardTerminal> terminals;
	private static SoftCard instance = null;
	private static Card card = null;
	private static CardChannel channel = null;
	private static Tunnel tunnel = null;
	private boolean unlocked = true; //false;


	private static String bytesToHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (byte b : bytes) {
			sb.append(String.format("0x%02x ", b));
		}
		return new String(sb);
	}

	private SoftCard() throws CardException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException, InterruptedException {
		factory = TerminalFactory.getDefault();
		terminals = factory.terminals().list();
		tunnel = new Tunnel(shared_key);

	}

	public static SoftCard getInstance() throws CardException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException, InterruptedException{
		if (instance == null) {
			instance = new SoftCard();
			CardTerminal terminal = terminals.get(0);

			/* Connexion à la carte */
			try {
				card = terminal.connect("T=1");
			}
			catch(CardException ce) {
				throw new CardException("Card removed.");
			}
			channel = card.getBasicChannel();
		}

		return instance;
	}


	/**
	 * This private method translates the PIN entered as an int to
	 * an array of two bytes.
	 * @param intPin
	 * @return the new pin, as a bytes's array
	 */
	private byte[] intToBytes(int intPin) {
		byte[] pin = new byte[2];
		pin[0] = (byte)(intPin >> 8);
		pin[1] = (byte)(intPin & 0x00FF);
		return pin;
	}

	/**
	 * This private method translates the PIN as an array of bytes to
	 * an int.
	 * @param bytesPin
	 * @return the new pin, as an integer.
	 */
	private int bytesToInt(byte[] bytesPin) {
		return (int)((bytesPin[0] & 0xFF) << 8 | (bytesPin[1] & 0xFF));
	}


	/**
	 * This method asks the user's PIN until it is correct or the card
	 * and is locked. In this case, the method askPuk is called().
	 */
	private void askPin() throws Exception {
		Console console = System.console();
		if (console == null) {
			System.err.println("Couldn't get Console instance.");
			disconnect();
			System.exit(1);
		}
		char[] tmpPin;
		byte res = 1;
		int pin;
		do  {
			try {
				tmpPin = console.readPassword("Enter your PIN: ");
				pin = Integer.parseInt(new String(tmpPin));
				res = unlock(intToBytes(pin));
			}
			catch(CardException ce) {
				disconnect();
				try {
					this.getInstance();
				} 
				catch (CardException ce1) {
					throw new Exception(ce1.getMessage());
				}
			}

			if (res == 0) {
				console.printf("Wrong PIN.\n");
			}
		} while (res == 0);

		if (res == -1) {
			System.err.println("Your smartcard is locked.");
			askPuk();
		}
		else if (res == 1) {
			console.printf("Valid PIN.\n");
		}
	}

	/**
	 * This method asks the user's PUK until it is correct or the card
	 * and is locked. In this case, the applets will have to be installed
	 * once again.
	 */
	private void askPuk() {
		Console console = System.console();
		if (console == null) {
			System.err.println("Couldn't get Console instance.");
			disconnect();
			System.exit(1);
		}

		char[] tmpPuk;
		int puk;
		byte[] pin = null;
		do {
			try {
				tmpPuk = console.readPassword("Enter your PUK: ");
				puk = Integer.parseInt(new String(tmpPuk));
				pin = unlockWithPuk(intToBytes(puk));

			}
			catch(Exception e) {}

			if (pin.length == 0) {
				console.printf("Wrong PUK.\n");
			}
		} while (pin != null && pin.length == 0);

		if (pin == null) {
			System.err.println("Your smartcard is definitely locked :( ");
			disconnect();
			System.exit(1);

		} else if (pin.length != 0) {
			console.printf("Your new PIN is : %d\n", bytesToInt(pin));
		}
	}


	public byte[] getPublicKey() throws Exception {
		try {
			/* Sélection de l'applet */
			ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, CIPHER_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}

			tunnel.erase();
			tunnel.request(AID_CYPHER, INS_GET_EXPONENT,(byte) 0x00, (byte)0x00);
			tunnel.execute();
			
			// Récupération de l'exposant
			/*r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_EXPONENT, 0x00, 0x00, 1));
			if (r.getSW() != 0x9000) {
				//throw new Exception("Could not retrieve the exponent.");
				throw new Exception("Err code : " + r.getSW());
			}*/

			BigInteger exp = new BigInteger(1, tunnel.getData());
			// Récupération du modulus
			
		/*	r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_MODULUS, 0x00, 0x00, 1));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not retrieve the modulus.");
			}*/
			
			tunnel.erase();
			tunnel.request(AID_CYPHER, INS_GET_MODULUS,(byte) 0x00, (byte)0x00);
			tunnel.execute();
			BigInteger mod = new BigInteger(1, tunnel.getData());
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(mod, exp);
			PublicKey publicKey = kf.generatePublic(pubKeySpec);
			return publicKey.getEncoded();
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return getPublicKey();
			} 
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}

	public void disconnect() {
		try {
			card.disconnect(false);
		}
		catch (Exception e) {}
		instance = null;
		unlocked = false;
	}

	public byte[] getRandomNumber(byte nb) throws Exception{
		try {
			/*// Selecting the applet
			ResponseAPDU r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, GEN_RANDOM_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet. : " + r.getSW());
			}*/

			tunnel.erase();
			tunnel.request(AID_RANDOM, INS_GEN,(byte) nb,(byte) 0x00);
			tunnel.execute();
			
			// Generating number 
			/*r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GEN, nb, 0x00));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not retrieve the random number.");
			}*/

			return tunnel.getData();
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return getRandomNumber(nb);
			} 
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}

	public byte[] decryptData(byte[] data) throws Exception {
		try {
			// Selecting the applet
			/*ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, CIPHER_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}
			// Decrypt data with the applet
			r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_UNCIPHER, 0x00, 0x00, data));
			if (r.getSW() == 0x4247) {
				throw new Exception("APDU Exception");
			}
			else if (r.getSW() == 0x0001) {
				throw new Exception("Unitialized key");
			}
			else if (r.getSW() == 0x0002) {
				throw new Exception("Invalid key");
			}
			else if (r.getSW() == 0x0003) {
				throw new Exception("Illegal use");
			}
			else if (r.getSW() == 0x0004) {
				throw new Exception("Illegal value");
			}
			else if (r.getSW() == 0x0005) {
				throw new Exception("No such algorithm");
			}
			else if (r.getSW() == 0x4249) {
				throw new Exception("Security exception");
			}*/

			tunnel.erase();
			tunnel.request(AID_CYPHER,INS_UNCIPHER, (byte)0x00,(byte) 0x00, data);
			tunnel.execute();
			
			byte[] res = tunnel.getData();

			if (res.length == 1 && res[0] == -1) {
				askPin();	
				return decryptData(data);
			}
			else {
				return res;
			}
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return decryptData(data);
			} 
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}

	public byte[] encryptData(byte[] data) throws Exception {
		try {
		/*	// Selecting the applet
			ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, (byte)0x04, 0x00, CIPHER_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}

			// Encrypt data with the applet
			r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_CIPHER, 0x00, 0x00, data));
			if (r.getSW() == 0x4247) {
				throw new Exception("APDU Exception");
			}
			else if (r.getSW() == 0x0001) {
				throw new Exception("Unitialized key");
			}
			else if (r.getSW() == 0x0002) {
				throw new Exception("Invalid key");
			}
			else if (r.getSW() == 0x0003) {
				throw new Exception("Illegal use");
			}
			else if (r.getSW() == 0x0004) {
				throw new Exception("Illegal value");
			}
			else if (r.getSW() == 0x0005) {
				throw new Exception("No such algorithm");
			}
			else if (r.getSW() == 0x4249) {
				throw new Exception("Security exception");
			}*/
			
			tunnel.erase();
			tunnel.request(AID_CYPHER,INS_CIPHER, (byte)0x00,(byte) 0x00, data);
			tunnel.execute();
			return tunnel.getData();
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return encryptData(data);
			} 
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}

	/**
	 * This method calls a method on the smartcard to check the validity of the PIN
	 * code. It first checks if the user is still allowed to enter such a PIN. 
	 * @param pin
	 * @return -1 if the user is not allowed to try again. 
	 * @return 0 if the PIN is wrong.
	 * @return 1 if the PIN is right.
	 * @throws Exception
	 */
	public byte unlock(byte[] pin) throws Exception {
		try {
			
			
			/*// Selecting the applet
			ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}*/
			
			
			// Checking if the card is PIN-locked
			tunnel.erase();
			tunnel.request(AID_PIN, INS_PIN_REMAINING_TRIES,(byte) 0x00,(byte) 0x00);
			tunnel.execute();
			/*r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_PIN_REMAINING_TRIES, 0x00, 0x00));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not check if the card was PIN-locked.");
			}*/

			if (tunnel.getData()[0] == 0) {
				return -1;
			}
			else {
				// Verify PIN
				/*r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_VERIF_PIN, SIZE_PIN, 0x00, pin));
				if (r.getSW() != 0x9000) {
					throw new Exception("Could not verify the PIN.");
				}*/
				tunnel.erase();
				tunnel.request(AID_PIN, INS_VERIF_PIN, SIZE_PIN, (byte) 0x00, pin);
				tunnel.execute();
				
				
				return tunnel.getData()[0];
			}

		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return unlock(pin);
			} 
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}


	/**
	 * This method calls another on the smartcard to check the validity of the PUK
	 * code. It first checks if the user is still allowed to enter such a PUK. If
	 * the operation succeeds the card is unlocked.  
	 * @param pin
	 * @return -1 if the user is not allowed to try again. 
	 * @return 0 if the PUK is wrong.
	 * @return 1 if the PUK is right.
	 * @throws Exception
	 */
	public byte[] unlockWithPuk(byte[] puk) throws Exception {
		try {
			// Selecting the applet
		/*	ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}*/
			// Checking if the card is PUK-locked
			/*r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_PUK_REMAINING_TRIES, 0x00, 0x00));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not check if the card was PUK-locked.");
			}*/
			tunnel.erase();
			tunnel.request(AID_PIN,INS_PUK_REMAINING_TRIES, (byte)0x00, (byte)0x00 );
			tunnel.execute();
			if (tunnel.getData()[0] == 0) {
				return null;
			}
			else {
				// Verify PUK
				/*r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_UNLOCK_WITH_PUK, SIZE_PUK, 0x00, puk));
				if (r.getSW() == 0x0001) {
					return new byte[]{};
				}*/
				
				tunnel.erase();
				tunnel.request(AID_PIN, INS_UNLOCK_WITH_PUK, (byte)SIZE_PUK,(byte) 0x00, puk);
				tunnel.execute();
				/*else if (r.getSW() != 0x9000) {
					throw new Exception("Could not verify the PUK.");
				}*/
			/*	else {*/
					return tunnel.getData();
				/*}*/
			}
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return unlockWithPuk(puk);
			} 
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}

	/**
	 * This method is called whenever SoftCard need to store a login and a password. It uses
	 * the methods storeLogin and storePassword.
	 * @param data - the data to store - built as follow: "login password"
	 * @return <code>true</code> if the data was successfully stored. 
	 * @throws Exception if the applet on the card could not be selected or if the data
	 * could not be stored. 
	 * @see storeLogin
	 * @see storePassword
	 */
	public boolean storeCredentials(byte[] data) throws Exception {
		int i = 0;
		boolean found = false; 

		// Recherche du motif " "(espace) servant de délimiteur
		while (i < data.length && !found) {
			if (data[i] == 0x20) {
				found = true;
			}
			else {
				i++;
			}
		}
		if (found) {
			byte[] login = new byte[i];
			byte[] mdp = new byte[data.length - i - 1];
			System.arraycopy(data, 0, login, 0, i);
			System.arraycopy(data, i + 1, mdp, 0, data.length - i - 1);

			return storeLogin(login) && storePassword(mdp);
		}
		else {
			throw new Exception("Could not store data.");
		}
	}

	/**
	 * This method is called whenever SoftCard need to store a login.
	 * @param login - the login to store
	 * @return <code>true</code> if the login was successfully stored. 
	 * @throws Exception if the applet on the card could not be selected or if the data
	 * could not be stored. 
	 */
	public boolean storeLogin(byte[] login) throws Exception {
		try {
		/*	// Selecting the applet
			ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, STORE_ID_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}*/
			// Store login
		/*	r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_STORE_LOGIN, 0x00, 0x00, login));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not store data." + r.getSW());
			}*/
			/*byte[] data = r.getData();*/

			tunnel.erase();
			tunnel.request(AID_STORE, INS_STORE_LOGIN,(byte) 0x00, (byte)0x00, login);
			tunnel.execute();
			byte[] data = tunnel.getData();
			
			if (data.length == 1 && data[0] == -1) {
				askPin();
				return storeLogin(login);
			}
			else {
				return (data[0] == 1) ? true : false;
			}
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return storeLogin(login);
			} 
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}

	/**
	 * This method is called whenever SoftCard need to store a password. If used with
	 * FaceCrypt, the password will only be stored temporary, unless FaceCrypt validates
	 * that the password was changed in Facebook.
	 * @param pwd - the password to store
	 * @return <code>true</code> if the password was successfully stored. 
	 * @throws Exception if the applet on the card could not be selected or if the data
	 * could not be stored. 
	 */
	private boolean storePassword(byte[] pwd) throws Exception {
		try {
		/*	// Selecting the applet
			ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte) 0xA4, 0x04, 0x00, STORE_ID_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}*/
			
			tunnel.erase();
			tunnel.request(AID_STORE,  INS_STORE_PWD,(byte) 0x00, (byte) 0x00, pwd);
			tunnel.execute();
			
			/*// Store temporary password
			r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_STORE_PWD, 0x00, 0x00, pwd));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not store data. " + r.getSW());
			}*/
			byte[] data = tunnel.getData();

			if (data.length == 1 && data[0] == -1) {
				askPin();
				return storePassword(pwd);
			}
			else {
				return (data[0] == 1) ? true : false;
			}
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return storePassword(pwd);
			}
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}


	/**
	 * This method is called whenever FaceCrypt send the message validating the password.
	 * @return true if no error occured while removing the old and the temporary password 
	 * @throws Exception if the applet on the card could not be selected or if the data
	 * could not be stored. 
	 */
	public boolean validatePassword() throws Exception {
		try {
			// Selecting the applet
			/*ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, STORE_ID_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}*/

			tunnel.erase();
			tunnel.request(AID_STORE,   INS_VALIDATE_PWD,(byte) 0x00,(byte) 0x00);
			tunnel.execute();
			
			
			// Send validation
			/*r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_VALIDATE_PWD, 0x00, 0x00));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not store data.");
			}*/
			return (tunnel.getData()[0] == 1) ? true : false;
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return validatePassword();
			}
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}	
		}
	}


	/**
	 * This method is called whenever FaceCrypt needs the user's credentials. 
	 * As a security mesure, the user will have to enter his PIN code.
	 * @return the login, the password and eventually the new password to be stored
	 * as one bytes' array. It also returns [-1] if the card is locked. 
	 * @throws Exception if the applet on the card could not be selected or if the data
	 * could not be retrieved. 
	 */
	public byte[] retrieveCredentials() throws Exception {
		try {
			// Selecting the applet
			/*ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, STORE_ID_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}*/

			tunnel.erase();
			tunnel.request(AID_STORE,   INS_GET_CRED, (byte)0x00,(byte) 0x00);
			tunnel.execute();
			
			
			// Retrieve data
			/*r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_CRED, 0x00, 0x00));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not retrieve data." + r.getSW());
			}*/
			byte[] data = tunnel.getData();

			if (data[0] == (byte)-1) {
				askPin();
				return retrieveCredentials();
			}
			else {
				return data;
			}
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return retrieveCredentials();
			}
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}
	/**
	 * This method allow the administrator to get the PIN unlocking the card.
	 * It will user another method on the card that will be callable only
	 * once.
	 * @throws Exception if the method was called more than once, or if another
	 * error occured on the smarcard's side.   
	 * @return the code PIN, as a bytes' array
	 */
	public byte[] getPIN() throws Exception{
		try {
			// Selecting the applet
		/*	ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}*/

			tunnel.erase();
			tunnel.request(AID_PIN,  INS_GET_PIN, (byte)0x00,(byte) 0x00);
			tunnel.execute();
			
			
			// Retrieve PIN
		/*	r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_PIN, 0x00, 0x00));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not retrieve code PIN.");
			}*/
			return tunnel.getData();
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return getPIN();
			}
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}

	/**
	 * This method allow the administrator to get the PUN unlocking the PIN.
	 * It will use another method on the card that will be callable only
	 * once.
	 * @throws Exception if the method was called more than once, or if another
	 * error occured on the smarcard's side.
	 * @return the code PUK, as a bytes' array
	 */
	public byte[] getPUK() throws Exception{
		try {
			// Selecting the applet
		/*	ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}*/

			tunnel.erase();
			tunnel.request(AID_PIN,   INS_GET_PUK, (byte)0x00, (byte)0x00);
			tunnel.execute();
			
			// Retrieve PUK
		/*	r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_PUK, 0x00, 0x00));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not retrieve PUK. " + r.getSW());
			}*/
			return tunnel.getData();
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return getPUK();
			}
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}

	/**
	 * This method is used to retrieve the current password in the bytes's array 
	 * returned by "retrieveCredentials".
	 * @return the current password, as a bytes' array.
	 */
	private byte[] getCurrentPassword() throws Exception {
		byte[] data = retrieveCredentials();
		if (data.length == 2) {
			return new byte[]{};
		}
		else {
			String tmpData = new String(data);
			return tmpData.substring(tmpData.lastIndexOf(" ") + 1).getBytes();
		}
	}

	/**
	 * This method allow the user to get a new password from the card.
	 * @throws Exception if an error occured on the smarcard's side.
	 * @return the old and the new password, as a bytes' array.
	 */
	public byte[] resetPassword() throws CardException, Exception {
		// Convert the generated password as something "readable"
		String password = Base64.encodeBase64String(getRandomNumber(SIZE_PWD));
		if(storePassword(password.getBytes())) {
			byte[] oldPwd = getCurrentPassword();
			byte[] newPwd = password.getBytes();
			byte[] delimiter = new byte[]{(byte)0x20};
			byte[] data = new byte[oldPwd.length + newPwd.length + delimiter.length];

			System.out.println(new String(oldPwd) + "|" + bytesToHexString(oldPwd));
			System.out.println(password + "|" + bytesToHexString(password.getBytes()));

			System.arraycopy(oldPwd, 0, data, 0, oldPwd.length);
			System.arraycopy(delimiter, 0, data, oldPwd.length, delimiter.length);
			System.arraycopy(newPwd, 0, data, oldPwd.length + delimiter.length, newPwd.length);

			System.out.println(new String(data));
			return data;
		}
		else { 
			return null;
		}
	}


	/**
	 * This method allow the user to get a new password from the card.
	 * @throws Exception if an error occured on the smarcard's side.
	 * @return the new password, as a bytes' array
	 */
	public boolean isUnlocked() throws Exception {
		try {
			// Selecting the applet
			/*ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not select the applet.");
			}*/
			tunnel.erase();
			tunnel.request(AID_PIN,  INS_IS_LOCKED, (byte)0x00,(byte) 0x00);
			tunnel.execute();
			
			/*
			// Retrieve PIN
			r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_PIN_REMAINING_TRIES, 0x00, 0x00));*/
			if (tunnel.getData().length == 0) {
				return false;
			}
			else {
				return true;
			}
		}
		catch(CardException ce) {
			try {
				disconnect();
				this.getInstance();
				return isUnlocked();
			}
			catch (CardException ce1) {
				throw new Exception(ce1.getMessage());
			}
		}
	}
}

