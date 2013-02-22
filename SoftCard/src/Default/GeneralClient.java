//package crypto;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;
import java.util.Scanner;

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

public class Crypto {
    /* Constantes */
    public static final byte CLA_CIPHER = (byte) 0xB0;

    public static final byte INS_CIPHER = 0x00;
    public static final byte INS_UNCIPHER = 0x01;
    public static final byte INS_GET_EXPONENT = 0x02;
    public static final byte INS_GET_MODULUS = 0x03;

    public static final byte INS_GEN = 0x00;

    private static final int INS_STORE_LOGIN = 0x00;
    private static final int INS_STORE_MDP = 0x01;
    private static final int INS_GET_CRED = 0x03;

    private static final int INS_PIN = 0x00;
    private static final int INS_PUK = 0x02;

    public static byte[] CIPHER_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x04 };
    public static byte[] RANDOM_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x01 };
    public static byte[] STORE_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x03 };
    public static byte[] PIN_AID = { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x08 };

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


            /* Menu principal */
            boolean fin = false;
            byte[] data = null;
            PublicKey publicKey = null;

            while (!fin) {
                System.out.println();
                System.out.println("Application cliente Javacard");
                System.out.println("----------------------------");
                System.out.println();
                System.out.println("1 - Récupérer la clef publique de chiffrement");
                System.out.println("2 - Chiffrer un message");
                System.out.println("3 - Déchiffrer un message");
                System.out.println("4 - Aléa");
                System.out.println("5 - Stocker identifiants");
                System.out.println("6 - Récupérer identifiants");
                System.out.println("7 - Check PIN");
                System.out.println("8 - Check PUK");
                System.out.println("9 - Quitter");
                System.out.println();
                System.out.println("Votre choix ?");

                int choix = System.in.read();
                while (!(choix >= '1' && choix <= '9')) {
                    choix = System.in.read();
                }

                BigInteger exp = null;
                switch (choix) {
                    case '1':
                        /* Sélection de l'applet */
                        r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, CIPHER_AID));
                        if (r.getSW() != 0x9000) {
                            System.out.println("Erreur lors de la sélection de l'applet : "+ r.getSW());
                            System.exit(1);
                        }

                        // Récupération de l'exposant
                        r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_GET_EXPONENT, (byte)0x00, (byte)0x00, 1));

                        if (r.getSW() != 0x9000) {
                            System.out.println("Err: " + r.getSW1() + " " + r.getSW2());
                        } else {
                            byte[] data1 = r.getData();
                            exp = new BigInteger(1, data1);
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
                            System.out.println(bytesToHexString(publicKey.getEncoded()));
                            System.out.println(publicKey.toString());
                        }
                        break;

                    case '2':
                        r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_CIPHER, (byte)0x00, (byte)0x00, ("hello world").getBytes()));
                        if (r.getSW() != 0x9000) {
                            System.out.println("Erreur : " + r.getSW1() + " " + r.getSW2());
                        } else {
                            data = r.getData();
                            System.out.println("Texte : " + bytesToHexString("hello world".getBytes()));
                            System.out.println("Chiffré : " + bytesToHexString(data));
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
                            System.out.println("Déchiffré " + bytesToHexString(data));
                        }
                        break;

                    case '4':
                        r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, RANDOM_AID));
                        if (r.getSW() != 0x9000) {
                            System.out.println("Erreur lors de la sélection de l'applet : "+ r.getSW());
                            System.exit(1);
                        }
                        r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_GEN, (byte) 2, (byte)0x00));
                        if (r.getSW() != 0x9000) {
                            System.out.println("Erreur : " + r.getSW());
                        } else {
                            System.out.println(bytesToHexString(r.getData()));
                        }

                        break;

                    case '5':
                        r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, STORE_AID));
                        if (r.getSW() != 0x9000) {
                            throw new Exception("Could not select the applet.");
                        }

                        byte[] stored = "maguy@toto.fr prout".getBytes(); 
                        String strStored = new String(stored);
                        int i = 0;
                        boolean stop = false;

                        while (i < strStored.length() && !stop) {
                            if (strStored.charAt(i) == ' ') {
                                stop = true;
                            }
                            else {
                                i++;
                            }
                        }

                        if (stop) {
                            byte[] login = new byte[i];
                            byte[] mdp = new byte[stored.length - i - 1];
                            System.arraycopy(stored, 0, login, 0, i);
                            System.arraycopy(stored, i + 1, mdp, 0, stored.length - i - 1);

                            System.out.println(login.length + "|" + new String(login) + "|");
                            System.out.println(mdp.length + "|" + new String(mdp) + "|");
                            // Store login
                            r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_STORE_LOGIN, 0x00, 0x00, login));
                            if (r.getSW() != 0x9000) {
                                throw new Exception("Could not store data.");
                            }

                            // Store mdp
                            r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_STORE_MDP, 0x00, 0x00, mdp));
                            if (r.getSW() != 0x9000) {
                                throw new Exception("Could not store data.");
                            }
                            System.out.println((r.getData()[0] == 1) ? true : false);
                        }
                        else {
                            throw new Exception("Could not store data");
                        }
                        break;

                    case '6':
                        // Selecting the applet
                        r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, STORE_AID));
                        if (r.getSW() != 0x9000) {
                            throw new Exception("Could not select the applet.");
                        }

                        // Retrieve data
                        r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_GET_CRED, 0x00, 0x00));
                        if (r.getSW() != 0x9000) {
                            throw new Exception("Could not retrieve data." + r.getSW());
                        }
                        else {
                            System.out.println(bytesToHexString(r.getData()));
                            System.out.println("Stocké : " + new String(r.getData()));
                        }
                        break;

                    case '7':
                        Scanner in = new Scanner(System.in);
                        int pin = in.nextInt();

                        byte[] data1 = new byte[2];
                        data1[0] = (byte)(pin >> 8);
                        data1[1] = (byte)(pin & 0xFF);
                        System.out.println(data1[0]);
                        System.out.println(data1[1]);

                        // Selecting the applet
                        r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
                        if (r.getSW() != 0x9000) {
                            throw new Exception("Could not select the applet.");
                        }

                        // Check PIN
                        r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_PIN, 0x02, 0x00, data1));
                        if (r.getSW() != 0x9000) {
                            throw new Exception("Could not retrieve data." + r.getSW());
                        }
                        else {
                            System.out.println("Res : " + bytesToHexString(r.getData()));
                        }

                        break;

                    case '8':
                        // Selecting the applet
                        r = channel.transmit(new CommandAPDU(0x00, (byte)0xA4, 0x04, 0x00, PIN_AID));
                        if (r.getSW() != 0x9000) {
                            throw new Exception("Could not select the applet.");
                        }

                        // Retrieve data
                        r = channel.transmit(new CommandAPDU((byte) CLA_CIPHER, INS_GET_CRED, 0x00, 0x00));
                        if (r.getSW() != 0x9000) {
                            throw new Exception("Could not retrieve data." + r.getSW());
                        }
                        else {
                            System.out.println("Stocké : " + new String(r.getData()));
                        }

                        break;

                    case '9':
                        fin = true;
                        break;
                }
            }

        } catch (CardException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
