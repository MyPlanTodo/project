//package monpack;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Timer;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class ClientTestCrypto {
	/* Constantes */
	public static final byte CLA_CIPHER = (byte) 0xB0;

	public static final byte INS_CIPHER = 0x00;
	public static final byte INS_UNCIPHER = 0x01;
	public static final byte INS_GET_EXPONENT = 0x02;
	public static final byte INS_GET_MODULUS = 0x03;
	public static final byte INS_TEST_AUTH = 0x04;
	public static final byte INS_ASK_AUTH = 0x05;

	public static byte[] CIPHER_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x01, (byte)0x00 };
	public static byte[] SIGN_AID= { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x02 };



	private static String bytesToHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (byte b : bytes) {
			sb.append(String.format("0x%02x ", b));
		}
		return new String(sb);
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException,
	NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
	BadPaddingException, NoSuchProviderException, IOException {
		int entier = 0;
		ResponseAPDU r, r1, r2, r3;
		byte[] clair = new String("Hello World").getBytes();

		if (args.length != 2) {
			System.out.println("Usage: time java ClientTestCrypto <(D)échiffrement | (C)hiffrement | (S)ignature | (V)érification>  <Nombre de tests>" );
			return;
		}

		if (!args[0].equals("C") && !args[0].equals("D") && !args[0].equals("c") && !args[0].equals("d") 
				&& !args[0].equals("S") && !args[0].equals("s") && !args[0].equals("V") && !args[0].equals("v")) {
			System.out.println("Usage: time java ClientTestCrypto <(D)échiffrement | (C)hiffrement | (S)ignature | (V)érification>  <Nombre de tests>" );
			return;
		}

		/* Connexion au lecteur */
		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terminals;
		try {
			terminals = factory.terminals().list();
			CardTerminal terminal = terminals.get(1);

			/* Connexion à la carte */
			Card card = terminal.connect("T=1");
			CardChannel channel = card.getBasicChannel();

			/* Sélection de l'applet */
			r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, CIPHER_AID));
			if (r.getSW() != 0x9000) {
				System.out.println("Erreur lors de la sélection de l'applet : "+ r.getSW());
				System.exit(1);
			}

			r2 = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, SIGN_AID));
			if (r2.getSW() != 0x9000) {
				System.out.println("Erreur lors de la sélection de l'applet : "+ r2.getSW());
				System.exit(1);
			}

			int compteur, actionNb = 0, testNb = Integer.parseInt(args[1]);
			if (args[0].equals("C") || args[0].equals("c"))
				actionNb = 1;
			if (args[0].equals("D") || args[0].equals("d"))
				actionNb = 2;
			if (args[0].equals("S") || args[0].equals("s"))
				actionNb = 3;
			if (args[0].equals("V") || args[0].equals("v"))
				actionNb = 4;


			switch (actionNb) {
			case 1:
				compteur = 0;
				while (compteur != testNb) {
					compteur++;
					System.out.println("Chiffrement n°"+ compteur);
					r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_CIPHER, (byte)0x00, (byte)0x00, ("hello word2").getBytes()));
					if (r.getSW() != 0x9000) {
						System.out.println("Erreur : " + r.getSW1() + " " + r.getSW2());
						System.out.println("Erreur : " + r.getSW());
					}
				}
				break;

			case 2:
				r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_CIPHER, (byte)0x00, (byte)0x00, ("hello word2").getBytes()));
				if (r.getSW() != 0x9000) {
					System.out.println("Erreur : " + r.getSW1() + " " + r.getSW2());
					System.out.println("Erreur : " + r.getSW());
				}
				compteur = 0;
				while (compteur != testNb) {
					compteur++;
					System.out.println("Déchiffrement n°"+ compteur);

					r1 = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_UNCIPHER, (byte)0x00, (byte)0x00, r.getData()));
					if (r1.getSW() != 0x9000) {
						System.out.println("ERREUR AU BOUT DE " + compteur + " TESTS");
						System.out.println("Erreur : " + r1.getSW1() + " " + r1.getSW2());
						System.out.println("Erreur : " + r1.getSW());
						break;
					} else {
						System.out.println(bytesToHexString(r1.getData()));
					}
				}
				break;

			case 3:

				compteur = 0;
				while (compteur != testNb) {
					compteur++;
					System.out.println("Signature n°" + compteur);
					System.out.print("clair : ");
					System.out.println(bytesToHexString(clair));


					r2 = channel.transmit(new CommandAPDU((byte)0xB0, INS_ASK_AUTH, (byte)0x00, (byte)0x00, clair));
					byte[] res = r.getData();
					if (r2.getSW() != 0x9000) {
						System.out.println("Erreur : "+ r2.getSW());
					} else {
						System.out.print("message signé: ");
						System.out.println(bytesToHexString(r2.getData()));
					}
				}
				break;
			case 4:
				/* On signe d'abord*/
				r2 = channel.transmit(new CommandAPDU((byte)0xB0, INS_ASK_AUTH, (byte)0x00, (byte)0x00, clair));
				byte[] res = r2.getData();
				if (r2.getSW() != 0x9000) {
					System.out.println("Erreur : "+ r2.getSW());
				} else {
					System.out.print("message signé: ");
					System.out.println(bytesToHexString(r2.getData()));
				}
				
				/* Puis on vérifie la signature testNb fois*/
				compteur = 0;
				while (compteur != testNb) {
					compteur++;
					System.out.println("Vérification n°" + compteur);

					r2 = channel.transmit(new CommandAPDU((byte)0xB0, INS_TEST_AUTH, (byte) 0x00, (byte)0x00, res));
					if (r2.getSW() != 0x9000) {
						System.out.println("Erreur : " + r2.getSW());
					}
					System.out.print("chiffré renvoyé : ");
					System.out.println(bytesToHexString(r2.getData()));

					r3 = channel.transmit(new CommandAPDU((byte)0xB0, INS_TEST_AUTH, (byte) 0x00, (byte)0x01, clair));
					System.out.print("vérifié??: ");
					System.out.println(bytesToHexString(r3.getData()));
				}

			default:
				System.out.println("default");
				break;

			}
		} catch (CardException e) {
			e.printStackTrace();
		}
	}
}
