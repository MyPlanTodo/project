// TODO : créer classe d'exception personelle

package Default;

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

/**
 * This class allow user to send requests to the smartcard :
 * cipher, uncipher, get the public key, sign data or verify it
 * @author Emmanuel Mocquet
 * @version 1.0
 */
public class Crypto {
	public static final byte CLA_CIPHER = (byte) 0xB0;

	// Constants identifying each applet on the smartcard
	public static byte[] GEN_RANDOM_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x00 };
	public static byte[] CIPHER_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01 };
	public static byte[] SIGN_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x02 };
	public static byte[] PIN_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x08 };
	public static byte[] TUNNEL_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x09 };

	// Constants associated with the generation of random number's applet
	public static final byte INS_GEN = 0x00;

	// Constants for verification and signature of data with the associated applet
	public static final byte INS_SIGN = 0x04;
	public static final byte INS_VERIF = 0x05;

	// Constants associated with the ciphering applet
	public static final byte INS_CIPHER = 0x00;
	public static final byte INS_UNCIPHER = 0x01;
	public static final byte INS_GET_EXPONENT = 0x02;
	public static final byte INS_GET_MODULUS = 0x03;

	// Constants associated with the applet handling the PIN code
	public static final byte INS_VERIF_PIN = 0x00;                              
	public static final byte INS_REMAINING_TRIES = 0x01;                        
	public static final byte INS_RESET_PIN = 0x02;                              
	public static final byte INS_UNLOCK_WITH_PUK = 0x03;  

	private TerminalFactory factory;
	private static List<CardTerminal> terminals;
	private static Crypto instance = null;
	private static Card card = null;
	private static CardChannel channel = null;
	private boolean unlocked = false;

	/*
	private static String bytesToHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (byte b : bytes) {
			sb.append(String.format("0x%02x ", b));
		}
		return new String(sb);
	}
	 */
	private Crypto() throws CardException {
		factory = TerminalFactory.getDefault();
		terminals = factory.terminals().list();

	}

	public static Crypto getInstance() throws CardException{
		if (instance == null) {
			instance = new Crypto();
			CardTerminal terminal = terminals.get(0);

			/* Connexion à la carte */
			card = terminal.connect("T=1");
			channel = card.getBasicChannel();
		}

		return instance;
	}

	public byte[] getPublicKey() throws Exception {
		/* Sélection de l'applet */
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, CIPHER_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}

		// Récupération de l'exposant
		r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_GET_EXPONENT, 0x00, 0x00, 1));
		if (r.getSW() != 0x9000) {
			//			throw new Exception("Could not retrieve the exponent.");
			System.out.println("Err code : " + r.getSW());
			throw new Exception("Err code : " + r.getSW());
		}

		BigInteger exp = new BigInteger(1, r.getData());
		// Récupération du modulus
		r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_GET_MODULUS, 0x00, 0x00, 1));
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

	public byte[] getRandomNumber(byte nb) throws Exception{
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, GEN_RANDOM_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}

		// Generating number 
		r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_GEN, nb, 0x00));
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
		r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_UNCIPHER, 0x00, 0x00, data));
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
		r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_CIPHER, 0x00, 0x00, data));
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

	public boolean isUnlocked(){
		return this.unlocked;
	}

	public boolean unlock(byte[] pin) throws Exception {
		// Selecting the applet
		ResponseAPDU r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
		if (r.getSW() != 0x9000) {
			throw new Exception("Could not select the applet.");
		}
		// Checking if the card is PIN-locked
		r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_REMAINING_TRIES, 0x00, 0x00));
		if (r.getSW() == 0x4247) {
			throw new Exception("APDU Exception");
		}
		
		if (r.getData()[0] < 0) {
			return false;
		}
		else {
			r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_VERIF_PIN, 0x00, 0x00, pin));
			if (r.getSW() == 0x4247) {
				throw new Exception("APDU Exception");
			}
			
		}
		return unlocked;
	}
}
