// TODO : créer classe d'exception personelle

//package Default;

import java.io.Console;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

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
 * @author Emmanuel Mocquet
 * @version 1.0
 */
public class SoftCard {
	public static final byte CLA_SMARTCARD = (byte) 0xB0;

	// Constants identifying each applet on the smartcard
	public static byte[] GEN_RANDOM_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01 };
	public static byte[] SIGN_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x02 };
	public static byte[] STORE_ID_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x03 };
	public static byte[] CIPHER_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x04 };
	public static byte[] PIN_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x08 };
	public static byte[] TUNNEL_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x09 };


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
	private boolean unlocked = true; //false;


	private static String bytesToHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (byte b : bytes) {
			sb.append(String.format("0x%02x ", b));
		}
		return new String(sb);
	}

	private SoftCard() throws CardException {
		factory = TerminalFactory.getDefault();
		terminals = factory.terminals().list();

	}

	public static SoftCard getInstance() throws CardException{
		if (instance == null) {
			instance = new SoftCard();
			CardTerminal terminal = terminals.get(0);

			/* Connexion à la carte */
			card = terminal.connect("T=1");
			channel = card.getBasicChannel();
		}

		return instance;
	}

	public static SoftCard getAdminInstance() throws CardException{
		if (instance == null) {
			instance = new SoftCard();
			CardTerminal terminal = terminals.get(0);

			/* Connexion à la carte */
			card = terminal.connect("T=1");
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
	private void askPin() {
		Console console = System.console();
		if (console == null) {
			System.err.println("Couldn't get Console instance.");
			try {
				disconnect();
			}
			catch(CardException ce) {
				System.err.println("Connection lost with the card.");
			}
			System.exit(1);
		}
		char[] tmpPin;
		byte res = 0;
		int pin;
		do  {
			try {
				tmpPin = console.readPassword("Enter your PIN: ");
				pin = Integer.parseInt(new String(tmpPin));
				res = unlock(intToBytes(pin));
			}
			catch(Exception e) {}
		} while (res == 0);

		if (res == - 1) {
			System.err.println("Your smartcard is locked.");
			askPuk();
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
			try {
				disconnect();
			}
			catch(CardException ce) {
				System.err.println("Connection lost with the card.");
			}
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
		} while (pin != null && pin.length == 0);

		if (pin == null) {
			System.err.println("Your smartcard is definitely locked :( ");
			try {
				disconnect();
			}
			catch(CardException ce) {
				System.err.println("Connection lost with the card.");
			}
			System.exit(1);

		} else if (pin.length != 0) {
			console.printf("Your new PIN is : %d\n", bytesToInt(pin));
		}
	}


	public byte[] getPublicKey() throws Exception {
		/* Sélection de l'applet */
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, CIPHER_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}

		// Récupération de l'exposant
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_EXPONENT, 0x00, 0x00, 1));
		if (r.getSW() != 0x9000) {
			//throw new Exception("Could not retrieve the exponent.");
			throw new Exception("Err code : " + r.getSW());
		}

		BigInteger exp = new BigInteger(1, r.getData());
		// Récupération du modulus
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_MODULUS, 0x00, 0x00, 1));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not retrieve the modulus.");
		}
		BigInteger mod = new BigInteger(1, r.getData());
		KeyFactory kf = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(mod, exp);
		PublicKey publicKey = kf.generatePublic(pubKeySpec);
		return publicKey.getEncoded();
	}

	public void disconnect() throws CardException{
		card.disconnect(false);
		instance = null;
		unlocked = false;
	}

	public byte[] getRandomNumber(byte nb) throws CardException, Exception{
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, GEN_RANDOM_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet. : " + r.getSW());
		}

		// Generating number 
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GEN, nb, 0x00));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not retrieve the random number.");
		}

		return r.getData();

	}

	public byte[] decryptData(byte[] data) throws Exception {
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, CIPHER_AID));
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
		}
		return r.getData();
	}

	public byte[] encryptData(byte[] data) throws Exception {
		// Selecting the applet
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
		}
		return r.getData();
	}

	/*
	 * TODO : Appeler une méthode de la carte !
	 */
	public boolean isUnlocked(){
		return this.unlocked;
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
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}
		// Checking if the card is PIN-locked
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_PIN_REMAINING_TRIES, 0x00, 0x00));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not check if the card was PIN-locked.");
		}

		if (r.getData()[0] == 0) {
			return -1;
		}
		else {
			// Verify PIN
			r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_VERIF_PIN, SIZE_PIN, 0x00, pin));
			if (r.getSW() != 0x9000) {
				throw new Exception("Could not verify the PIN.");
			}

			return r.getData()[0];
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
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}
		// Checking if the card is PUK-locked
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_PUK_REMAINING_TRIES, 0x00, 0x00));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not check if the card was PUK-locked.");
		}

		if (r.getData()[0] == 0) {
			return null;
		}
		else {
			// Verify PUK
			r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_UNLOCK_WITH_PUK, SIZE_PUK, 0x00, puk));
			if (r.getSW() == 0x0001) {
				return new byte[]{};
			}
			else if (r.getSW() != 0x9000) {
				throw new Exception("Could not verify the PUK.");
			}
			else {
				return r.getData();
			}
		}
	}

	/**
	 * This method is called whenever SoftCard need to store a login and a password. It uses
	 * the methods storeLogin and storePassword.
	 * @param data - the data to store - built as follow: "login password"
	 * @return <code>true</code> if the data was successfully stored. 
	 * @throws Exception - if the applet on the card could not be selected or if the data
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
	 * @throws Exception - if the applet on the card could not be selected or if the data
	 * could not be stored. 
	 */
	public boolean storeLogin(byte[] login) throws Exception {
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, STORE_ID_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}
		// Store login
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_STORE_LOGIN, 0x00, 0x00, login));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not store data." + r.getSW());
		}
		byte[] data = r.getData();
		
		if (data[0] == -1) {
			askPin();
			return storeLogin(login);
		}
		else {
			return (data[0] == 1) ? true : false;
		}
	}

	/**
	 * This method is called whenever SoftCard need to store a password. If used with
	 * FaceCrypt, the password will only be stored temporary, unless FaceCrypt validates
	 * that the password was changed in Facebook.
	 * @param pwd - the password to store
	 * @return <code>true</code> if the password was successfully stored. 
	 * @throws Exception - if the applet on the card could not be selected or if the data
	 * could not be stored. 
	 */
	private boolean storePassword(byte[] pwd) throws Exception {
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte) 0xA4, 0x04, 0x00, STORE_ID_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}
		// Store temporary password
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_STORE_PWD, 0x00, 0x00, pwd));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not store data. " + r.getSW());
		}
		byte[] data = r.getData();

		if (data[0] == -1) {
			askPin();
			return storePassword(pwd);
		}
		else {
			return (data[0] == 1) ? true : false;
		}
	}


	/**
	 * This method is called whenever FaceCrypt send the message validating the password.
	 * @return true if no error occured while removing the old and the temporary password 
	 * @throws Exception - if the applet on the card could not be selected or if the data
	 * could not be stored. 
	 */
	public boolean validatePassword() throws Exception {
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, STORE_ID_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}

		// Send validation
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_VALIDATE_PWD, 0x00, 0x00));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not store data.");
		}
		return (r.getData()[0] == 1) ? true : false;
	}


	/**
	 * This method is called whenever FaceCrypt needs the user's credentials. 
	 * As a security mesure, the user will have to enter his PIN code.
	 * @return the login, the password and eventually the new password to be stored
	 * as one bytes' array. It also returns [-1] if the card is locked. 
	 * @throws Exception - if the applet on the card could not be selected or if the data
	 * could not be retrieved. 
	 */
	public byte[] retrieveCredentials() throws Exception {
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, STORE_ID_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}

		// Retrieve data
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_CRED, 0x00, 0x00));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not retrieve data." + r.getSW());
		}
		byte[] data = r.getData();
		
		if (data[0] == (byte)-1) {
			askPin();
			return retrieveCredentials();
		}
		else {
			return data;
		}
	}

	/**
	 * This method allow the administrator to get the PIN unlocking the card.
	 * It will user another method on the card that will be callable only
	 * once.
	 * @throws Exception - if the method was called more than once, or if another
	 * error occured on the smarcard's side.   
	 * @return the code PIN, as a bytes' array
	 */
	public byte[] getPIN() throws Exception{
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}

		// Retrieve PIN
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_PIN, 0x00, 0x00));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not retrieve code PIN.");
		}
		return r.getData();
	}

	/**
	 * This method allow the administrator to get the PUN unlocking the PIN.
	 * It will use another method on the card that will be callable only
	 * once.
	 * @throws Exception - if the method was called more than once, or if another
	 * error occured on the smarcard's side.
	 * @return the code PUK, as a bytes' array
	 */
	public byte[] getPUK() throws Exception{
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}

		// Retrieve PUK
		r = channel.transmit(new CommandAPDU((byte) CLA_SMARTCARD, INS_GET_PUK, 0x00, 0x00));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not retrieve PUK. " + r.getSW());
		}
		return r.getData();
	}

	/**
	 * This method allow the user to get a new password from the card.
	 * @throws Exception - if an error occured on the smarcard's side.
	 * @return the new password, as a bytes' array
	 */
	public byte[] resetPassword() throws Exception {
		// Convert the generated password as something "readable"
		String password = Base64.encodeBase64String(getRandomNumber(SIZE_PWD));
		return storePassword(password.getBytes()) ? password.getBytes() : null;
	}
}

