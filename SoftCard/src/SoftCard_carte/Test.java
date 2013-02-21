

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
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

public class Test {
	/* Constantes */
	public static final byte CLA_CIPHER = (byte) 0xB0;

	public static final byte INS_CIPHER = 0x00;
	public static final byte INS_UNCIPHER = 0x01;
	public static final byte INS_GET_EXPONENT = 0x02;
	public static final byte INS_GET_MODULUS = 0x03;
	public static final byte INS_TEST_AUTH = 0x04;
	public static final byte INS_ASK_AUTH = 0x05;
	public static final byte INS_NOUVEL_ALEA = 0x06;

	public static byte[] CIPHER_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x01, (byte)0x00 };
	public static byte[] SIGN_AID= { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x02 };
	public static byte[] GEN_AID= { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x03 };

	private  final static SecretKey shared_key = new SecretKeySpec(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6}, "AES");



	private static String bytesToHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (byte b : bytes) {
			sb.append(String.format("0x%02x ", b));
		}
		return new String(sb);
	}

	public static void main(String[] args) throws Exception {

		ResponseAPDU r, r1, r2, r3, r4;
		byte[] clair = new String("Hello World").getBytes();


		/* Connexion au lecteur */
		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terminals;
		try {
			terminals = factory.terminals().list();
			CardTerminal terminal = terminals.get(1);

			/* Connexion à la carte */
			Card card = terminal.connect("T=1");
			CardChannel channel = card.getBasicChannel();


			boolean fin = false;
			while (!fin) {
				System.out.println();
				System.out.println("Application cliente Javacard");
				System.out.println("----------------------------");
				System.out.println();
				System.out.println("1 - chiffrement RSA");
				System.out.println("2 - déchifremment RSA");
				System.out.println("3 - signature");
				System.out.println("4 - vérification");
				System.out.println("5 - Génération d'un nombre aléatoire");
				System.out.println("6 - Quitter");
				System.out.println();
				System.out.println("Votre choix ?");
				Tunnel t = new Tunnel(shared_key);
				int choix = System.in.read();
				while (!(choix >= '1' && choix <= '5')) {
					choix = System.in.read();
				}


				switch (choix) {
				case '1':
					/* Sélection de l'applet */
					r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, CIPHER_AID));
					if (r.getSW() != 0x9000) {
						System.out.println("Erreur lors de la sélection de l'applet : "+ r.getSW());
						System.exit(1);
					}

					System.out.println("Clair: " + bytesToHexString(clair));


					r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_CIPHER, (byte)0x00, (byte)0x00, clair));
					if (r.getSW() != 0x9000) {
						System.out.println("Erreur : " + r.getSW1() + " " + r.getSW2());
						System.out.println("Erreur : " + r.getSW());
					} else {
						System.out.println("Chiffré: " + bytesToHexString(r.getData()));
					}				
					break;

				case '2':
					/* Sélection de l'applet */
					r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, CIPHER_AID));
					if (r.getSW() != 0x9000) {
						System.out.println("Erreur lors de la sélection de l'applet : "+ r.getSW());
						System.exit(1);
					}

					System.out.println("Clair: " + bytesToHexString(clair));
					r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_CIPHER, (byte)0x00, (byte)0x00, clair));
					if (r.getSW() != 0x9000) {
						System.out.println("Erreur : " + r.getSW1() + " " + r.getSW2());
						System.out.println("Erreur : " + r.getSW());
					} else {
						System.out.println("Chiffré : " + bytesToHexString(r.getData()));
					}

					r1 = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_UNCIPHER, (byte)0x00, (byte)0x00, r.getData()));
					if (r1.getSW() != 0x9000) {
						System.out.println("Erreur : " + r1.getSW1() + " " + r1.getSW2());
						System.out.println("Erreur : " + r1.getSW());
					} else {
						System.out.println("Déchiffré : " + bytesToHexString(r1.getData()));
					}

					break;

				case '3':

					/*r2 = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, SIGN_AID));



					if (r2.getSW() != 0x9000) {
						System.out.println("Erreur lors de la sélection de l'applet : "+ r2.getSW());
						System.exit(1);
					}*/
					t.erase();
					t.request((short) 0x04, INS_ASK_AUTH, (byte)0x00, (byte)0x00, clair);
					System.out.println("Clair :" + bytesToHexString(clair));
					//r2 = channel.transmit(new CommandAPDU((byte)0xB0, INS_ASK_AUTH, (byte)0x00, (byte)0x00, clair));
					/*if (r2.getSW() != 0x9000) {
						System.out.println("Erreur : "+ r2.getSW());
					} else {
						System.out.print("Message signé: ");
						System.out.println(bytesToHexString(r2.getData()));
					}*/
					t.execute();
					byte[] dechiff = t.getDataMAC();
					System.out.print("Message signé: ");
					System.out.println(bytesToHexString(dechiff));
					break;

				case '4':
					/*r2 = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, SIGN_AID));
					if (r2.getSW() != 0x9000) {
						System.out.println("Erreur lors de la sélection de l'applet : "+ r2.getSW());
						System.exit(1);
					}*/
					t.erase();
					t.request((short) 0x04,  INS_ASK_AUTH, (byte)0x00, (byte)0x00, clair);
					t.execute();
					/* On signe d'abord*/
					/*System.out.println("Clair :" + bytesToHexString(clair));
					r2 = channel.transmit(new CommandAPDU((byte)0xB0, INS_ASK_AUTH, (byte)0x00, (byte)0x00, clair));
					 */
					byte[] signed = t.getDataMAC();

					System.out.print("Message signé: ");
					System.out.println(bytesToHexString(signed));


					t.erase();
					t.request((short) 0x04, INS_TEST_AUTH, (byte) 0x00, (byte)0x00, signed);
					t.execute();					
					byte[] res2 =  t.getDataMAC();
					System.out.print("Chiffré renvoyé : ");
					System.out.println(bytesToHexString(res2));
					
					t.erase();
					t.request((short) 0x04, INS_TEST_AUTH, (byte) 0x00, (byte)0x01, clair);
					t.execute();
					/*r3 = channel.transmit(new CommandAPDU((byte)0xB0, INS_TEST_AUTH, (byte) 0x00, (byte)0x01, clair));
					System.out.print("vérifié?? ");*/
					System.out.println("(0x00 = vérifié; 0x01 = non vérifié) : " +bytesToHexString(t.getDataMAC()));
					break;

				case '5':
					r4 = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, GEN_AID));
					if (r4.getSW() != 0x9000) {
						System.out.println("Erreur lors de la sélection de l'applet : "+ r4.getSW());
						System.exit(1);
					}




					t.erase();
					t.request((short)1, (short)0,(byte)100,(byte)0);
					t.execute();
					t.getResponse();



					r4 = channel.transmit(new CommandAPDU((byte)0xB0, INS_NOUVEL_ALEA, (byte) 0x79, (byte)0x00));
					System.out.println("Nombre aléatoire : " + bytesToHexString(r4.getData()));
					break;

				default:
					//System.out.println("default");
					fin = true;

					break;

				}
			}
		} catch (CardException e) {
			e.printStackTrace();
		}

	}
}
