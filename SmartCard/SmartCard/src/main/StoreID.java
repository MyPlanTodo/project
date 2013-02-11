package main;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

public class StoreID extends Applet {
	/* Constantes */
	public static final byte CLA_STORE = (byte) 0xB0;
	public static final byte INS_STORE = 0x00;		

	private byte[] credentials;
	private byte[] buffer;
	private short dataLen;


	/* Constructeur */
	private StoreID() {
		credentials = null;
		//	buffer = JCSystem.makeTransientByteArray((short) 96, JCSystem.CLEAR_ON_RESET);
	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new StoreID().register();
	}


	public void process(APDU apdu) throws ISOException {
		buffer = apdu.getBuffer();

		if (this.selectingApplet()) return;

		if (buffer[ISO7816.OFFSET_CLA] != CLA_STORE) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {
		case INS_STORE:
			try{
				dataLen = apdu.setIncomingAndReceive();
				Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, credentials, (short) 0, dataLen);
				buffer[0] = 0;
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} catch(Exception e) {
				buffer[0] = 1;
				apdu.setOutgoingAndSend((short) 0, (short) 1);
				break;
			}

		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}