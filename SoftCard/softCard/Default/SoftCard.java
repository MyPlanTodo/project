package Default;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.smartcardio.CardException;


/**
 * This class will create a multi-thread Server.
 * It is able to listen clients and send them an
 * hard-coded message 
 * @author Baptiste Dolbeau, Emmanuel Mocquet
 * @version 1.0
 */
public class SoftCard {

	static SSLServerSocket servSocket;
	private InetAddress adresse = null;
	static ProcessusSock ps = null;


	/**
	 * This constructor initialize a Server.
	 * First it translates the string address
	 * into an InetAddress object.
	 * Then it set up the SSL Context (certificate,
	 * etc). 
	 * Finally it creates an SSL Socket listening
	 * on the port specified.
	 * @param adr Is the address of the server.
	 * @param port Is the port on which the server will listen.
	 * @param maxConn Specify the number of connection allowed.
	 */
	public SoftCard(String adr, int port, int maxConn) {
		try {
			adresse = Inet4Address.getByName(adr);			
		} catch (UnknownHostException e) {
			System.out.println("Adresse non valide");
			e.printStackTrace();
			System.exit(1);
		}

		setContext();
		SSLServerSocketFactory sslSrvFact = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();

		try {
			servSocket = (SSLServerSocket) sslSrvFact.createServerSocket(port, maxConn, adresse);
			this.listening();
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Problème Socket");
			System.exit(2);
		}
	}

	/**
	 * This method set up the SSL context. It specify the
	 * keystore which contains the server's certificate
	 * and its public key. 
	 */
	public void setContext() {
		System.setProperty("javax.net.ssl.keyStore", "/home/maguy/certs/carte.jks");
		System.setProperty("javax.net.ssl.keyStorePassword", "lolilol");
		System.setProperty("javax.net.ssl.trustStore", "/home/maguy/certs/trustClientFaceCrypt.jks");
		System.setProperty("javax.net.ssl.trustStorePassword", "lolilol");
	}

	/**
	 * This method make the server in listening mode.
	 * For each client connection, it create an object
	 * which extends thread.
	 */
	public void listening() {
		SSLSocket sock = null;
		while (true) {
			try {
				sock = (SSLSocket) servSocket.accept();
				ps = new ProcessusSock(sock);
			} catch (IOException e) {
				System.out.println("Problème Ecoute Socket");
				System.exit(3);
			}
		}
	}
}	


/**
 * This class represents a client thread.
 * It has few methods for its management.
 * 
 * @author Baptiste Dolbeau, Emmanuel Mocquet
 * @version 1.0
 */
class ProcessusSock extends Thread {

	private SSLSocket socket = null;
	private DataInputStream in = null;
	private DataOutputStream out = null;

	private final byte QUIT = (byte) 0x00;
	private final byte GET_KEY = (byte) 0x42;
	private final byte GET_RANDOM_NUMBER = (byte) 0x43;
	private final byte DECRYPT= (byte) 0x44;
	private final byte IS_UNLOCKED = (byte) 0x45;
	private final byte UNLOCK = (byte) 0x46;
	private final byte STORE_CREDENTIALS = (byte) 0x47;
	/**
	 * This constructor links a reader and
	 * a printer to the socket and start
	 * the thread.
	 * 
	 * @param socket The client's socket.
	 * @throws IOException
	 */
	public ProcessusSock(SSLSocket socket) throws IOException {
		this.socket = socket;
		try {
			in = new DataInputStream(socket.getInputStream());
			out = new DataOutputStream(socket.getOutputStream());	
			this.start();
		} catch (IOException e) {
			free();
		}
	}

//	private static String bytesToHexString(byte[] bytes) {
//		StringBuffer sb = new StringBuffer();
//		for (byte b : bytes) {
//			sb.append(String.format("0x%02x ", b));
//		}
//		return new String(sb);
//	}

	/**
	 * This method will be executed by the
	 * thread. It follows the rule :
	 * One message received, One message sent.
	 * 
	 * An identifier is sent to the server (us), to inform it the task to do.
	 */
	public void run() {
		byte[] mess = {};
		boolean cont = true;

		do {
			try {
				mess = receiveMessages();
				cont = doAction(mess);
			} catch (Exception e) {
				System.err.println("Error while sending data.");
				cont = false;
			}
		} while (cont);

		try {
			this.disconnectCard();
			free();
		} catch (IOException e) {
			System.err.println("An error occured while closing connection.");
		} catch (CardException e) {
			System.err.println("An error occured while disconnecting the card.");
		}
	}

	private boolean doAction(byte[] mess) throws IOException {
		boolean res = true;
		if (mess.length > 0) {
			byte id = mess[0];

			// Send public key
			if (id == this.GET_KEY) {
				try {
					byte[] key = this.getPublicKey();
					sendMessage(key);
				} catch(CardException ce) {
					sendMessage("Error while establishing connection with the card.".getBytes());
				} catch (Exception e) {
					sendMessage("Error while obtaining the public key.".getBytes());
				}
			}

			// Send random number
			else if (id == this.GET_RANDOM_NUMBER) {
				byte nb = mess[1];
				try {
					sendMessage(this.getRandomNumber(nb));
				} catch(CardException ce) {
					sendMessage("Error while establishing connection with the card.".getBytes());
				} catch (Exception e) {
					e.printStackTrace();
					sendMessage("Error while obtaining a random number".getBytes());
				}
			}
			// retrieve the ciphered data and decrypt it.
			else if (id == this.DECRYPT) {
				System.out.println("decrypt");
				byte[] data = new byte[mess.length - 1];

				System.arraycopy(mess, 1, data, 0, mess.length - 1);
				try {
					sendMessage(this.decryptData(data));
				} catch (Exception e) {
					sendMessage("An error occured while decrypting data".getBytes());
				}
			}
			// check if the card is unlocked.
			else if (id == this.IS_UNLOCKED) {
				try {
					sendMessage((isUnlocked())? new byte[]{1} : new byte[]{0});
				} catch (CardException e) {
					sendMessage("An error occured while checking the card's activation".getBytes());
				}
			}
			else if (id == this.UNLOCK) {
				byte[] data = new byte[mess.length - 1];
				System.arraycopy(mess, 1, data, 0, mess.length - 1);
				try {
					sendMessage(unlock(data)? new byte[]{1} : new byte[]{0});
				} catch (Exception e) {
					sendMessage("An error occured while unlocking card".getBytes());
				}
			}
			else if (id == this.STORE_CREDENTIALS) {
				byte[] data = new byte[mess.length - 1];
					
				try {
					sendMessage(storeData(data)? new byte[]{1} : new byte[]{0});
				} catch (Exception e) {
					sendMessage("An error occured while storing data".getBytes());

				}
			}
			// client wants to disconnect.
			else if (id == this.QUIT){
				res = false;
			}
		}

		return res;
	}

	/**
	 * This method calls the eponymous method of {@link Crypto} to 
	 * store the user's login and password. 
	 * @param data 
	 * @return true if the all went well.
	 * @throws Exception - with the reason message, if an error
	 * occured on the smartcard's side.
	 */
	private boolean storeData(byte[] data) throws Exception {
		return Crypto.getInstance().storeData();
	}
	
	/**
	 * This method calls the eponymous method of {@link Crypto} to 
	 * verify the unlocking of the smartcard.
	 * @return true if the Card if the card is unlocked, false otherwise
	 * @throws CardException - with the reason message, if an error
	 * occured on the smartcard's side.
	 */
	private boolean isUnlocked() throws CardException {
		return Crypto.getInstance().isUnlocked();		
	}

	/**
	 * This method calls the eponymous method of {@link Crypto} to 
	 * verify the PIN.
	 * @return true if the Card if the PIN is correct, false otherwise
	 * @throws Exception - with the reason message, if an error
	 * occured on the smartcard's side.
	 */
	private boolean unlock(byte[] pin) throws Exception {
		return Crypto.getInstance().unlock(pin);
	}

	/**
	 * This method calls disconnectCard from {@link Crypto} to
	 * obtain a random number.
	 * @throws CardException - with the reason message, if an error
	 * occured on the smartcard's side.
	 * @see Crypto
	 */
	private void disconnectCard() throws CardException {
		Crypto.getInstance().disconnect();
	}

	/**
	 * This method calls getRandomNumber from {@link Crypto} to obtain
	 * a random number.
	 * @return an random number in a bytes' array
	 * @throws Exception - with the reason message
	 * @see Crypto
	 */
	private byte[] getRandomNumber(byte nb) throws Exception {
		Crypto c = Crypto.getInstance();
		return c.getRandomNumber(nb);
	}

	/**
	 * This method calls decryptData from {@link Crypto} to obtain
	 * the decrypted data.
	 * @return the decrypted data in a bytes' array
	 * @throws Exception - with the reason message
	 * @see Crypto
	 */
	private byte[] decryptData(byte[] data) throws Exception {
		Crypto c = Crypto.getInstance();
		return c.decryptData(data);
	}

	/**
	 * This method calls getPublicKey from {@link Crypto} to obtain
	 * the public key stored in the smartcard.
	 * @return the public key in a bytes' array
	 * @throws Exception - with the reason message
	 * @throws CardException - if an error occured on the smartcard's side
	 * @see Crypto
	 */
	private byte[] getPublicKey() throws CardException, Exception {
		Crypto c = Crypto.getInstance();
		byte[] publicKey = c.getPublicKey();
		return publicKey;
	}

	/**
	 * This method will retrieve a response from
	 * the DataOutputStream. It will first read the
	 * length of data to receive, then read it.
	 * @return The received data and its length
	 * @throws IOException
	 */
	private byte[] receiveMessages() throws IOException {
		int i = in.readInt();

		if (i > 2560 ) {
			throw new IOException("Data too big");
		}

		byte[] b = new byte[i];
		in.read(b, 0, i);
		return b;
	}

	/**
	 * This method will write data into
	 * the DataInputStream object to send on the socket.
	 * It will first write the length's data, then the data
	 * itself. 
	 * Finally, it flushes the buffer.
	 * @param s The data and its length to send
	 * @throws IOException
	 */
	private void sendMessage(byte[] b) throws IOException {
		out.writeInt(b.length);
		out.write(b, 0, b.length);
		out.flush();
	}

	/**
	 * This method closes the printer and reader
	 * and closes the socket.
	 * @throws IOException
	 */
	private void free () throws IOException {
		in.close();
		out.close();
		socket.close();
	}
}


