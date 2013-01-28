package crypto;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;


public class Cypher extends Applet {


	/* Constantes */
	public static final byte CLA_MONAPPLET = (byte) 0xB1;

	public static final byte INS_CIPHER = 0x00;
	public static final byte INS_UNCIPHER = 0x01;
	private static final byte INS_GET_EXPONENT = 0x02;
	private static final byte INS_GET_MODULUS = 0x03;

	private PrivateKey privKey;
	private PublicKey pubKey;
	private KeyPair kp;

	/* Constructeur */
	private Cypher(){
		try{
			kp = new KeyPair(KeyPair.ALG_RSA_CRT, (short) KeyBuilder.LENGTH_RSA_512);
			kp.genKeyPair();
			privKey = (PrivateKey) kp.getPrivate();
			pubKey = (PublicKey) kp.getPublic();
		}
		catch(CryptoException e){
			ISOException.throwIt((short) 0x4242);
		}
	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		// Register à comprendre
		new Cypher().register();//bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		short dataLen;
		Cipher cipher;
		short cipherLen = 0;

		if (this.selectingApplet()){
			return;
		}

		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {

		// Requête de chiffrement
		case INS_CIPHER:
			try {
				dataLen = apdu.setIncomingAndReceive();
				cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

				cipher.init(pubKey, Cipher.MODE_ENCRYPT);
				cipherLen = cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, dataLen, buffer, ISO7816.OFFSET_CDATA);

				// Besoin d'utiliser ces fonctions pour des réponses "longues"
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) cipherLen);
				apdu.sendBytesLong(buffer, (short) ISO7816.OFFSET_CDATA, (short) cipherLen);

				//apdu.setOutgoingAndSend((short) 0, (short) cipherLen);
			}
			catch(APDUException e){
				ISOException.throwIt((short) 0x4244);
			}
			catch(CryptoException e){
				ISOException.throwIt((short) 0x4245);
			}
			catch(SecurityException e){
				ISOException.throwIt((short) 0x4246);
			}

			break;

			// Requête de déchiffrement
		case INS_UNCIPHER:
			try {
				dataLen = apdu.setIncomingAndReceive();
				cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

				cipher.init(privKey, Cipher.MODE_DECRYPT);
				cipherLen = cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, dataLen, buffer, ISO7816.OFFSET_CDATA);

				// Besoin d'utiliser ces fonctions pour des réponses "longues"
				apdu.setOutgoing();
				apdu.setOutgoingLength((short) cipherLen);
				apdu.sendBytesLong(buffer, (short) ISO7816.OFFSET_CDATA, (short) cipherLen);
			}
			catch(APDUException e){
				ISOException.throwIt((short) 0x4247);
			}
			catch(CryptoException e){
				ISOException.throwIt((short) 0x4248);
			}
			catch(SecurityException e){
				ISOException.throwIt((short) 0x4249);
			}

			break;

		case INS_GET_EXPONENT:
			try {
				RSAPublicKey rsaPubKey= (RSAPublicKey) pubKey;
				dataLen = rsaPubKey.getExponent(buffer, (short) 0);
				apdu.setOutgoingAndSend((short) 0, (short) dataLen);
			}
			catch(APDUException e){
				ISOException.throwIt((short) 0x4242);
			}
			catch(SecurityException e){
				ISOException.throwIt((short) 0x4243);
			}
			break;

		case INS_GET_MODULUS:
			try {
				RSAPublicKey rsaPubKey= (RSAPublicKey) pubKey;
				dataLen = rsaPubKey.getModulus(buffer, (short) 0);
				apdu.setOutgoingAndSend((short) 0, (short) dataLen);
			}
			catch(APDUException e){
				ISOException.throwIt((short) 0x4242);
			}
			catch(SecurityException e){
				ISOException.throwIt((short) 0x4243);
			}
			break;


		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
