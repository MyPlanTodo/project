/* Author : Romain Pignard */

/* 
 * Applet generating random numbers 
 * 
 * 
 * 
 */



package store;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.RandomData;


public class gen_random extends Applet {
	
	public static final byte CLA_MONAPPLET = (byte) 0xB0;
	
	public static final byte INS_NOUVEL_ALEA = 0x00;
	
	
	/* Attributs */
	
	private static RandomData rng;
	private static short[] lg;
	public static void execute(byte[] data)
	{
		switch (data[ISO7816.OFFSET_INS]) {
		
		case INS_NOUVEL_ALEA:
			// the required number is in big endian
			lg[0] = (short) (data[ISO7816.OFFSET_P1] + data[ISO7816.OFFSET_P2]*256) ;
			// 
			datastore.eraseData();
			rng.generateData(data, (short) 0,(short) lg[0]);			
			datastore.putData(data, lg[0]);
			
			break;
		}
		
	}

	private gen_random() {
		// Secure random number generator
		rng =  RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		
		// number of random bytes needed
		lg = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);	
		lg[0] = 0;
		
	}
	
	
	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new gen_random().register();
	}
	
	
	public static  void genRandom(byte[] buff , short nb)
	{
		// buff : output buffer
		// nb : required number of bytes
		
		
		try{
		rng =  RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		
		// we put the required number of random bytes into buff
		rng.generateData(buff,(short) 0,(short) nb);
		}
		catch(CryptoException ce)
		{
			if(ce.getReason() == CryptoException.ILLEGAL_USE)
			{ISOException.throwIt((short) 0x01);}
			else if (ce.getReason() == CryptoException.ILLEGAL_VALUE)
			{ISOException.throwIt((short) 0x02);}
			else if (ce.getReason() == CryptoException.INVALID_INIT)
			{ISOException.throwIt((short) 0x03);}
			else if (ce.getReason() == CryptoException.NO_SUCH_ALGORITHM)
			{ISOException.throwIt((short) 0x04);}
			else if (ce.getReason() == CryptoException.UNINITIALIZED_KEY)
			{ISOException.throwIt((short) 0x05);}
			
		}
	}
	
	public void process(APDU apdu) throws ISOException {
		
		byte[] buffer = apdu.getBuffer();
		
		
		
		if (this.selectingApplet()) return;
		
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		
		switch (buffer[ISO7816.OFFSET_INS]) {
		
		case INS_NOUVEL_ALEA:
			
			lg[0] = buffer[ISO7816.OFFSET_P1];
			
			rng.generateData(buffer, (short) 0,(short) lg[0]);
			
			apdu.setOutgoingAndSend((short) 0, (short) lg[0]);
			break;
		
		default:
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}	

	}

}
