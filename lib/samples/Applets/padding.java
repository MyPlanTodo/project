/* Author : Romain Pignard */

package store;

import javacard.framework.APDU;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.crypto.*;

public class padding extends Applet {
	private static byte[] padded;	
	private static short[] tab;
	
	public static final byte CLA_MONAPPLET = (byte) 0xB0;
	
	public static final byte INS_PAD = 0x00;
	public static final byte INS_UNPAD = 0x01;
	
	

	private padding() {
		// padded contains is the temporary storage for the (un)padded message
		padded = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
		
		// tab is a temporary short array for loop variables and array length
		tab = JCSystem.makeTransientShortArray((short) 8, JCSystem.CLEAR_ON_RESET);
	}

	public static void install(byte bArray[], short bOffset, byte bLength)
			throws ISOException {
		new padding().register();
	}

	public static short pad(byte[] sortie, byte[] entree, short blockSize, short lg, byte bufOff)
	{
					
		// copy of the original message into padded 
		
		Util.arrayCopy(entree, (short)bufOff,padded ,(short) 0,lg);
		
		/*for(tab[0] = 0; tab[0] < (short) (lg); tab[0]++)
		{
			padded[tab[0]] = entree[(short)(tab[0]+bufOff)];
		}*/
		// padding of the message according to pkcs7			
		
		if(lg % blockSize == 0)
		{	
			// if the last block is full, we create another full block 
			
			Util.arrayFillNonAtomic(padded, lg, (short) (  blockSize), (byte)  blockSize);
			
			/*for( tab[0] = (short) lg; tab[0] < (short) (lg +  blockSize) ; tab[0]++)
			{
				
				padded[tab[0]] = (byte)  blockSize;
			}*/
		}
		else
		{
			// we fill the last block with the required number of bytes
			
			Util.arrayFillNonAtomic(padded, lg, (short) (  blockSize  -  (lg % blockSize)), (byte) ((byte)  blockSize - lg  % blockSize));
			
			/*for(tab[0] =(short) lg; tab[0] < (short) (lg + blockSize -  (lg % blockSize)); tab[0]++)
			{
				padded[tab[0]] = (byte) (blockSize - lg  % blockSize);
			}*/
		}
		tab[1] = (short) (lg + blockSize -  (lg % blockSize));
		//tab[1] = (short)( lg - entree[(short)(lg - 1 + bufOff)]);
		
		Util.arrayCopy(padded, (short)0,sortie ,(short) 0,tab[1] );
		/*for( tab[0] = 0;tab[0]<tab[1];tab[0]++)
		{
			sortie[tab[0]] = padded[tab[0]]; 
			
		}*/
		
		
		// length of the padded message
		return tab[1];
	}	
	
	public static short unpad(byte[] buffIn,byte[] mess, short blockSize, short lg, short bufOff)
	{
		
		// removing of the padding
		
		Util.arrayCopy(mess, (short)bufOff,padded ,(short) 0,(short)( lg - mess[(short)(lg-1 +bufOff) ]) );
		
		/*for(tab[(short)0] = 0; tab[(short)0] <(short)( lg - mess[(short)(lg-1 +bufOff) ]);tab[(short)0]++ )
		{
			padded[tab[0]] = mess[(short)(tab[0] + bufOff)];
			
		}*/
		tab[1] = (short)( lg - mess[(short)(lg - 1 + bufOff)]);
		
		Util.arrayCopy(padded, (short)0,buffIn ,(short) 0, tab[1]);
	/*	for( tab[0] = 0;tab[0]<tab[1];tab[0]++)
		{
			buffIn[tab[0]] = padded[tab[0]]; 
			
		}	*/
		
		
		
		// length of the unpadded message
		return tab[1];				
	}
	
	
	
	public void process(APDU apdu) throws ISOException {
		byte[] buffer = apdu.getBuffer();
		
		
		if (this.selectingApplet()) return;
		
		if (buffer[ISO7816.OFFSET_CLA] != CLA_MONAPPLET) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		switch (buffer[ISO7816.OFFSET_INS]) {
			case INS_UNPAD:			
				tab[1] =   unpad(buffer,buffer,buffer[ISO7816.OFFSET_P2],buffer[ISO7816.OFFSET_P1],ISO7816.OFFSET_CDATA);				
				break;
			case INS_PAD:
				tab[1] =  pad(buffer,buffer,buffer[ISO7816.OFFSET_P2],buffer[ISO7816.OFFSET_P1],ISO7816.OFFSET_CDATA);
				break;
			default:
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
						
		apdu.setOutgoingAndSend((short) 0, tab[1]);

	}

}
