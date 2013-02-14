import Default.SoftCard;


public class getCode {
	private static String bytesToHexString(byte[] bytes) {
		StringBuffer sb = new StringBuffer();
		for (byte b : bytes) {
			sb.append(String.format("0x%02x ", b));
		}
		return new String(sb);
	}

	public static void main(String[] args) {
		try {
			if (args.length == 1) {
				SoftCard soft = SoftCard.getInstance();
				if (args[0].equals("PIN")) {
					byte[] b = soft.getPIN();
					System.out.println(bytesToHexString(b));
					int value = b[0];
					value = (int) ((value << 8) | b[1]);
					System.out.println(String.format("%06d", value));
				}
				else if (args[0].equals("PUK")) {
					byte[] b = soft.getPUK();
					System.out.println(bytesToHexString(b));
					short value = b[0];
					value = (short) ((value << 8) | b[1]);
					System.out.println(String.format("%06d", value));
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
