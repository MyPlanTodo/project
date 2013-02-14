package Default;

/**
 * This class abstracts the errors sent to the client if necessary.
 * @author Emmanuel Mocquet
 *
 */
public enum NetworkException {
	
	ERROR_CONNECTION_CARD(new byte[]{-1}),
	ERROR_PUBKEY(new byte[]{-2}),
	ERROR_RANDOM_NUMBER(new byte[]{-3}),
	ERROR_DECRYPT(new byte[]{-4}),
	ERROR_UNLOCK_CARD(new byte[]{-5}),
	ERROR_CHECK_LOCKED(new byte[]{-6}),
	ERROR_STORE_ID(new byte[]{-7}),
	ERROR_GET_ID(new byte[]{-8}),
	ERROR_RESET_PASSWORD(new byte[]{-9});
	
	private byte[] value;

	private NetworkException(byte[] b) {
		System.arraycopy(b, 0, value, 0, b.length);
	}
	
	public byte[] getValue() {
		return this.value;
	}
}
