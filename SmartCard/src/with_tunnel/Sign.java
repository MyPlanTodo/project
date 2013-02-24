package with_tunnel;


import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyPair;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;
import javacard.security.Signature;

public class Sign extends Applet {


	/* Constantes */
	public static final byte CLA_MONAPPLET = (byte) 0xB0;

	public static final byte INS_TEST_AUTH = 0x04;
	public static final byte INS_ASK_AUTH = 0x05;

	public static final byte MAX_BYTES = 117;

	private PrivateKey privKey;
	private PublicKey pubKey;
	private static Signature signature;
	private static Signature signature1;

	private static byte[] clair = null;
	private static byte[] signe = null;
	private static short dataLen;
	private static short dataLen1;


	/* Constructeur */
	private Sign() {
		/* Préparation du couple de clé */
		KeyPair kp = new KeyPair(KeyPair.ALG_RSA_CRT, (short)1024);
		/* génération de la bi-clé */
		kp.genKeyPair();
		/* On récupère la clé privée */
		privKey = (PrivateKey) kp.getPrivate();
		/* On récupère la clé publique */
		pubKey = (PublicKey) kp.getPublic();

		signe = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_RESET);
		clair = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_RESET);

		/* Choix de l'algorithme de signature */
		signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		/* On définit le mode (signature) */
		signature.init(privKey, Signature.MODE_SIGN);

		/* Choix de l'algorithme de signature */
		signature1 = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		/* On définit le mode (vérification) */
		signature1.init(pubKey, Signature.MODE_VERIFY);

	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new Sign().register();
	}


	public static void execute(byte[] data)
	{
		switch (data[ISO7816.OFFSET_INS]) {


		case INS_TEST_AUTH:
			/* réception du clair(buffer) et vérification*/
			if (data[ISO7816.OFFSET_P2] == (byte) 1) {
				dataLen = data[ISO7816.OFFSET_LC];
				
				try {
					/* Si le message est authentifié alors on renvoie 0x00 */
					if (signature1.verify(data, (short) ISO7816.OFFSET_CDATA, dataLen, signe, (short) 0, dataLen1)) {
						data[0] = 0x00;
						datastore.eraseData();
						datastore.putData(data, (short) 1);
					} else { /* 0x01 sinon */ 
						data[0] = 0x01;
						datastore.eraseData();
						datastore.putData(data, (short) 1);
					}
				} catch (CryptoException c) {
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

				/* réception du signé et sauvegarde de celui ci*/
			} else {
				try {
					dataLen1 = (short) -data[ISO7816.OFFSET_LC];
					if (dataLen1 > 255) {
						ISOException.throwIt((short) 0x0128);
						//throw new IllegalArgumentException("Clair trop grand!!!");
					}

					Util.arrayCopy(data, (short)ISO7816.OFFSET_CDATA, signe, (short)0, dataLen1);
					datastore.eraseData();
					datastore.putData(signe, dataLen1);
				} catch (APDUException a) {
					ISOException.throwIt((short) 0x01);
				}
				catch (ArrayIndexOutOfBoundsException a) {
					ISOException.throwIt((short) 0x02);
				}
				catch (NullPointerException a) {
					ISOException.throwIt((short) 0x03);
				}
				catch (TransactionException a) {
					ISOException.throwIt((short) 0x04);
				}
			}

			break;	
			
			
			
		case INS_ASK_AUTH:
			dataLen = data[ISO7816.OFFSET_LC];

			/* On le signe et on récupère la taille du signé */
			short len1 = (short) signature.sign(data, ISO7816.OFFSET_CDATA, dataLen, data, (short) 0);
			//ISOException.throwIt(len1);
			try {
				/* Envoie du message signé */
				/*apdu.setOutgoing();
				apdu.setOutgoingLength(len1);
				apdu.sendBytesLong(buffer, (short) 0, len1);*/
				datastore.eraseData();
				datastore.putData(data, len1);
			} catch (CryptoException c){
				ISOException.throwIt((short) 0x4243);
			} catch (APDUException a) {
				ISOException.throwIt((short) 0x4144);
			}
			break;
			
			
		}
	}



	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();



		if (this.selectingApplet()){
			return;
		}

		/* On vérifie le CLA de l'applet */
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}



		switch (buffer[ISO7816.OFFSET_INS]) {

		/* Requête de chiffrement */

		/* Vérification du message signé */
		case INS_TEST_AUTH:
			/* réception du clair(buffer) et vérification*/
			if (buffer[ISO7816.OFFSET_P2] == (byte) 1) {
				dataLen = apdu.setIncomingAndReceive();

				try {

					/* Si le message est authentifié alors on renvoie 0x00 */
					if (signature1.verify(buffer, (short) ISO7816.OFFSET_CDATA, dataLen, signe, (short) 0, dataLen1)) {
						buffer[0] = 0x00;
						apdu.setOutgoingAndSend((short) 0, (short) 1);
					} else { /* 0x01 sinon */ 
						buffer[0] = 0x01;
						apdu.setOutgoingAndSend((short) 0, (short) 1);
					}
				} catch (CryptoException c) {
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

				/* réception du signé et sauvegarde de celui ci*/
			} else {
				try {
					dataLen1 = apdu.setIncomingAndReceive();
					if (dataLen1 > 255) {
						ISOException.throwIt((short) 0x0128);
						//throw new IllegalArgumentException("Clair trop grand!!!");
					}

					javacard.framework.Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, signe, (short)0, dataLen1);

					apdu.setOutgoing();
					apdu.setOutgoingLength(dataLen1);
					apdu.sendBytesLong(signe, (short) 0, dataLen1);
				} catch (APDUException a) {
					ISOException.throwIt((short) 0x01);
				}
				catch (ArrayIndexOutOfBoundsException a) {
					ISOException.throwIt((short) 0x02);
				}
				catch (NullPointerException a) {
					ISOException.throwIt((short) 0x03);
				}
				catch (TransactionException a) {
					ISOException.throwIt((short) 0x04);
				}
			}

			break;		



			/* Signature du message clair et envoie */
		case INS_ASK_AUTH:
			dataLen = apdu.setIncomingAndReceive();

			/* On le signe et on récupère la taille du signé */
			short len1 = signature.sign(buffer, ISO7816.OFFSET_CDATA, dataLen, buffer, (short) 0);

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
