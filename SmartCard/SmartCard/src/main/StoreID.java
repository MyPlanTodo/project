package main;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.framework.Util;

public class StoreID extends Applet {
	/* Constantes */
	public static final byte CLA_STORE = (byte) 0xB0;
	public static final byte INS_STORE_LOGIN = 0x00;
	public static final byte INS_STORE_MDP = 0x01;
	public static final byte INS_GET = 0x02;		

	private byte[] login, delimiter, mdp;
	private short[] dataLen;

	/* Constructeur */
	private StoreID() {
		login = null; 
		// This delimiter represent a ' ' (space).
		delimiter = new byte[]{0x20};
		mdp = null;

		// Will contain the length of the received data.
		dataLen = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
		dataLen[0] = 0;
	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new StoreID().register();
	}


	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();

		if (this.selectingApplet()) return;

		if (buffer[ISO7816.OFFSET_CLA] != CLA_STORE) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {
		/**
		 * Store the provided login.
		 */
		case INS_STORE_LOGIN:
			try{
				dataLen[0] = apdu.setIncomingAndReceive();
				login = new byte[dataLen[0]];
				Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, login, (short) 0, dataLen[0]);

				buffer[0] = 1;
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} catch(APDUException e) {
				ISOException.throwIt((short) 0x0001);
			} catch(NullPointerException e) {
				ISOException.throwIt((short) 0x0002);
			} catch(ArrayIndexOutOfBoundsException e) {
				ISOException.throwIt((short) 0x0003);
			} catch(TransactionException e) {
				ISOException.throwIt((short) 0x0004);
			}
			break;

			/**
			 * Store the provided password.
			 */
		case INS_STORE_MDP:
			try{
				dataLen[0] = apdu.setIncomingAndReceive();
				mdp = new byte[dataLen[0]];
				Util.arrayCopy(buffer, (short)ISO7816.OFFSET_CDATA, mdp, (short) 0, dataLen[0]);

				buffer[0] = 1;
				apdu.setOutgoingAndSend((short) 0, (short) 1);
			} catch(APDUException e) {
				ISOException.throwIt((short) 0x0001);
			} catch(NullPointerException e) {
				ISOException.throwIt((short) 0x0002);
			} catch(ArrayIndexOutOfBoundsException e) {
				ISOException.throwIt((short) 0x0003);
			} catch(TransactionException e) {
				ISOException.throwIt((short) 0x0004);
			}
			break;


			/**
			 * Copy login+delimiter+password into the buffer and send it
			 */
		case INS_GET:
			try{
				Util.arrayCopy(login, (short) 0, buffer, (short) 0, (short) login.length);
				Util.arrayCopy(delimiter, (short) 0, buffer, (short) login.length, (short) delimiter.length);
				Util.arrayCopy(mdp, (short) 0, buffer, (short) (login.length + delimiter.length), (short) mdp.length);

				apdu.setOutgoing();
				apdu.setOutgoingLength((short)(login.length + mdp.length + delimiter.length));
				apdu.sendBytesLong(buffer, (short) 0, (short)(login.length + mdp.length + delimiter.length));
			} catch(APDUException e) {
				ISOException.throwIt((short) 0x0001);
			} catch(NullPointerException e) {
				ISOException.throwIt((short) 0x0002);
			} catch(ArrayIndexOutOfBoundsException e) {
				ISOException.throwIt((short) 0x0003);
			} catch(TransactionException e) {
				ISOException.throwIt((short) 0x0004);
			}
			break;

		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
