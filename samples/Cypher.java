package crypto;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;

public class Cypher extends Applet {


	/* Constantes */
	public static final byte CLA_MONAPPLET = (byte) 0xB1;

	public static final byte INS_CIPHER = 0x00;
	public static final byte INS_UNCIPHER = 0x01;
	public static final byte INS_GEN_CIPHER_KEY = 0x02;

	private RSAPrivateKey privKey;
	private RSAPublicKey pubKey;

	/* Constructeur */
	private Cypher() {
		KeyPair kp = new KeyPair(KeyPair.ALG_RSA, (short)1024);
		kp.genKeyPair();
		privKey = (RSAPrivateKey) kp.getPrivate();
		pubKey = (RSAPublicKey) kp.getPublic();
	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new Cypher().register();
	}

	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		short dataLen;
		Cipher cipher;
		short cipherLen;

		if (this.selectingApplet()){
			return;
		}

		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {

		/* Requête de chiffrement */
		case INS_CIPHER:
			dataLen = apdu.setIncomingAndReceive();
			cipher = Cipher.getInstance(Cipher.ALG_RSA_ISO14888, false);

			cipher.init(pubKey, Cipher.MODE_ENCRYPT);
			cipherLen = cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, dataLen, buffer, ISO7816.OFFSET_CDATA);

			/* Besoin d'utiliser ces fonctions pour des réponses "longues" */
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) cipherLen);
			apdu.sendBytesLong(buffer, (short) ISO7816.OFFSET_CDATA, (short) cipherLen);

			//apdu.setOutgoingAndSend((short) 0, (short) cipherLen);

			break;

		/* Requête de déchiffrement */
		case INS_UNCIPHER:
			dataLen = apdu.setIncomingAndReceive();
			cipher = Cipher.getInstance(Cipher.ALG_RSA_ISO14888, false);

			cipher.init(privKey, Cipher.MODE_DECRYPT);
			cipherLen = cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, dataLen, buffer, ISO7816.OFFSET_CDATA);

			/* Besoin d'utiliser ces fonctions pour des réponses "longues" */
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) cipherLen);
			apdu.sendBytesLong(buffer, (short) ISO7816.OFFSET_CDATA, (short) cipherLen);

			break;

		/* Requête de génération d'une bi-clef 
		 * La clef étant générée à l'installation de l'applet, il suffit de la retourner */
		case INS_GEN_CIPHER_KEY:
			apdu.setOutgoing();
			apdu.setOutgoingLength(pubKey.getSize());
			apdu.sendBytesLong(buffer, (short) ISO7816.OFFSET_CDATA, (short) pubKey.getSize());
			break;

		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
