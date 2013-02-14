package Admin;

import Default.SoftCard;

/**
 * This class allow the administrator to get (only once) the code PIN and PUK
 * stored on the smartcard. An error may be thrown if the PIN or the PUK has already
 * been requested. 
 * @param an argument (PIN or PUK) is expected to obtain the concerned one.
 * @author Emmanuel Mocquet
 *
 */
public class getCode {
	public static void main(String[] args) {
		try {
			byte[] b;
			short value1, value2;
			
			/*
			 * XX & 0xFF : conversion en non signé
			 */
			if (args.length == 1) {
				SoftCard soft = SoftCard.getInstance();
				if (args[0].equals("PIN")) {
					b = soft.getPIN();
					value1 = (short) ((b[0] < 0) ? (b[0] & 0xFF) : b[0]);
					value2 = (short) ((b[1] < 0) ? (b[1] & 0xFF) : b[1]);
					System.out.println(String.format("%05d", (short)(value1 * 256 + value2)));
				}
				else if (args[0].equals("PUK")) {
					b = soft.getPUK();
					value1 = (short) ((b[0] < 0) ? (b[0] & 0xFF) : b[0]);
					value2 = (short) ((b[1] < 0) ? (b[1] & 0xFF) : b[1]);
					System.out.println(String.format("%05d", (short)(value1 * 256 + value2)));
				}
				else {
					System.err.println("Usage : getCode <PIN|PUK> ");
					System.exit(1);
				}
			}
			else {
				System.err.println("Usage : getCode <PIN|PUK> ");
				System.exit(1);
			}
		} catch (Exception e) {
			System.err.println("Error " + e.getMessage());
		} 
	}

}
