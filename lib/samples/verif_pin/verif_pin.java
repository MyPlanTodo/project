package verif_pin;


import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;

public class verif_pin extends Applet {
	public static final byte CLA_MONAPPLET = (byte) 0xB0;
	public static final byte VERIF_PIN = 0x00;
	private OwnerPIN pin;
	private byte [] pin_value = {12};

	private verif_pin() {		
		pin.update(pin_value,(short) 0, (byte) 4 );
				
	}

	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new verif_pin().register();
	}

	
	public void process(APDU apdu) throws ISOException {

		//récupération du buffer
		byte[] buffer = apdu.getBuffer();
		
		
		
		if (this.selectingApplet()) return;
		
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (buffer[ISO7816.OFFSET_INS]) {
		
		case VERIF_PIN:
			pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) 1);
			
			if( pin.isValidated())
			{
				buffer[0] = 1;
			}
			else
			{
				buffer[0] = 0;
			}
			apdu.setOutgoingAndSend((short) 0, (short) 4);
			break;
		
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}	

	

	}

}
