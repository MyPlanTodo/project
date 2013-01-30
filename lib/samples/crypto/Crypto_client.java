package crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

import org.apache.commons.codec.binary.Base64;

public class Crypto {
	/* Constantes */
	public static final byte CLA_CIPHER = (byte) 0xB1;

	public static final byte INS_CIPHER = 0x00;
	public static final byte INS_UNCIPHER = 0x01;
	public static final byte INS_GET_EXPONENT = 0x02;
	public static final byte INS_GET_MODULUS = 0x03;

	public static byte[] CIPHER_AID = { (byte)0x02, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x00 };

	private static String bytesToHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (byte b : bytes) {
			sb.append(String.format("0x%02x ", b));
		}
		return new String(sb);
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		ResponseAPDU r;

		/* Connexion au lecteur */
		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terminals;
		try {
			terminals = factory.terminals().list();
			CardTerminal terminal = terminals.get(0);

			/* Connexion à la carte */
			Card card = terminal.connect("T=1");
			CardChannel channel = card.getBasicChannel();

			/* Sélection de l'applet */
			r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, CIPHER_AID));
			if (r.getSW() != 0x9000) {
				System.out.println("Erreur lors de la sélection de l'applet : "+ r.getSW());
				System.exit(1);
			}

			/* Menu principal */
			boolean fin = false;
			byte[] chiffre = null;

			PublicKey publicKey = null;

			while (!fin) {
				System.out.println();
				System.out.println("Application cliente Javacard");
				System.out.println("----------------------------");
				System.out.println();
				System.out.println("1 - Récupérer la clef publique de chiffrement");
				System.out.println("2 - Chiffrer un message");
				System.out.println("3 - Déchiffrer un message");
				System.out.println("4 - Quitter");
				System.out.println();
				System.out.println("Votre choix ?");

				int choix = System.in.read();
				while (!(choix >= '1' && choix <= '4')) {
					choix = System.in.read();
				}

				BigInteger exp = null;
				switch (choix) {
				case '1':
					// Récupération de l'exposant
					r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_GET_EXPONENT, (byte)0x00, (byte)0x00, 1));

					if (r.getSW() != 0x9000) {
						System.out.println("Err: " + r.getSW1() + " " + r.getSW2());
					} else {
						byte[] data = r.getData();
						exp = new BigInteger(1, data);
						System.out.println(exp.toString());
					}

					// Récupération du modulus
					r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_GET_MODULUS, (byte)0x00, (byte)0x00, 1));

					if (r.getSW() != 0x9000) {
						System.out.println("Err: " + r.getSW1() + " " + r.getSW2());
					} else {
						BigInteger mod = new BigInteger(1, r.getData());

						KeyFactory kf = KeyFactory.getInstance("RSA");
						RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(mod, exp);
						publicKey = kf.generatePublic(pubKeySpec);
						System.out.println(publicKey.toString());

					}
					break;

				case '2':
					r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_CIPHER, (byte)0x00, (byte)0x00, ("hello world").getBytes()));
					byte[] data = null;
					if (r.getSW() != 0x9000) {
						System.out.println("Erreur : " + r.getSW1() + " " + r.getSW2());
					} else {
						data = r.getData();
						System.out.println("|" + bytesToHexString("hello world".getBytes()) + "|");
						System.out.println("|" + bytesToHexString(data) + "|");
					}
					break;

				case '3':
					Cipher c = Cipher.getInstance("RSA");
					byte[] clearText = new String("hello world").getBytes();
					c.init(Cipher.ENCRYPT_MODE, publicKey);
					byte[] ciphered = c.doFinal(clearText);
					System.out.println("Clair : " + bytesToHexString(clearText));
					System.out.println("Chiffré : " + bytesToHexString(ciphered));
					System.out.println("Taille chiffré : " + ciphered.length);

					r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_UNCIPHER, (byte) 0x00, (byte)0x00, ciphered));

					if (r.getSW() != 0x9000) {
						System.out.println("Erreur : " + r.getSW());
					} else {
						data = r.getData();
						System.out.println(bytesToHexString(data));
					}
					break;

				case '4':
					fin = true;
					break;
				}
			}

			/* Mise hors tension de la carte */
			card.disconnect(false);

		} catch (CardException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}