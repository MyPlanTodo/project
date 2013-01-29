package myPackage;
/**
 * @author: DTGio
 */


import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.Signature;

public class Crypto extends Applet {


	/* Constantes */
	public static final byte CLA_MONAPPLET = (byte) 0xB0;

	public static final byte INS_TEST_AUTH = 0x02;
	public static final byte INS_ASK_AUTH = 0x03;

	private PrivateKey privKey;
	private PublicKey pubKey;
	private Signature signature;
	private Signature signature1;

	/* Constructeur */
	private Crypto() {
		KeyPair kp = new KeyPair(KeyPair.ALG_RSA_CRT, (short)1024);
		kp.genKeyPair();
		privKey = (PrivateKey) kp.getPrivate();
		pubKey = (PublicKey) kp.getPublic();
	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new Crypto().register();
	}

	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();

		if (this.selectingApplet()){
			return;
		}

		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}


		switch (buffer[ISO7816.OFFSET_INS]) {

		/* Requête de chiffrement */

		/* Vérification du message signé */
		case INS_TEST_AUTH:
			/* Message clair qui a été signé */
			byte[] test1 = {0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08};

			try {
				signature1 = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
				signature1.init(pubKey, Signature.MODE_VERIFY);
				
				/* taille du message signé convertit en short positif */
				short p1 = (short) (buffer[ISO7816.OFFSET_P1] & 0xFF);
				
				/* Si le message est authentifié alors on renvoie 0x00 */
				if (signature1.verify(test1, (short) 0, (short) test1.length, buffer, (short) ISO7816.OFFSET_CDATA, p1)) {
					buffer[0] = 0x00;
					apdu.setOutgoingAndSend((short) 0, (short) 1);
				} else { /* 0x01 sinon */ 
					buffer[0] = 0x01;
					apdu.setOutgoingAndSend((short) 0, (short) 1);
				}
			} catch (CryptoException c){
				if(c.getReason() == CryptoException.UNINITIALIZED_KEY)
					ISOException.throwIt((short) 0x4242);
				else if(c.getReason() == CryptoException.INVALID_INIT)
					ISOException.throwIt((short) 0x4243);
				else if(c.getReason() == CryptoException.ILLEGAL_USE)
					ISOException.throwIt((short) 0x4244);
				else
					ISOException.throwIt((ISO7816.SW_RECORD_NOT_FOUND));

			} catch (APDUException a) {
				ISOException.throwIt((short) 0x4141);
			}
			break;
		
		/* Signature du message clair*/
		case INS_ASK_AUTH:
			signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
			signature.init(privKey, Signature.MODE_SIGN);		
			
			/* Message clair à signé */
			byte[] test2 = {0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08};
			/* On le signe et on récupère la taille du signé */
			short len1 = signature.sign(test2, (short) 0, (short) test2.length, buffer, (short) 0);

			try {
				/* Envoie du message signé */
				apdu.setOutgoing();
				apdu.setOutgoingLength(len1);
				apdu.sendBytesLong(buffer, (short) 0, len1);
			} catch (CryptoException c){
				ISOException.throwIt((short) 0x4243);
			} catch (APDUException a) {
				ISOException.throwIt((short) 0x4144);
			}
			break;

		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
