/* Author : Romain Pignard */

package store;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;

public class echo extends Applet {

	public static final byte CLA_MONAPPLET = (byte) 0xB0;
	
	private static short[] lg;
	private static byte[] buf;
	private echo() {
		lg = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
		buf = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_RESET);
	}

	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new echo().register();
	}

	public static void execute(byte[] buffer)
	{
		datastore.putData(buffer,buffer[ISO7816.OFFSET_LC], ISO7816.OFFSET_CDATA);		
	}
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		
		
		if (this.selectingApplet()) return;
				
				if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
					ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
				}
				
		lg[2] = buffer[ISO7816.OFFSET_LC];		
		for(lg[1] = 0; lg[1]< lg[2];lg[1]++)
		{
			buf[lg[1]] = buffer[(short)(ISO7816.OFFSET_CDATA + lg[1])];			
		}	
		for(lg[1] = 0; lg[1]< lg[2];lg[1]++)
		{
			buffer[lg[1]] = buf[lg[1]];			
		}	
		apdu.setOutgoingAndSend((short) 0, (short) lg[1]);	
	}

}
