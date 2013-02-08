import java.util.Random;






public class ArrayTools {	
	
	
	public static void printByteArray(byte[] array)
	{
		for(int i = 0; i< array.length;i++ )
		{
			System.out.print(array[i]+" ");
		}
		System.out.println();
		
	}
	public static void printByteArray(byte[] array, short max)
	{
		byte[][] splitted = split(array,max);
		
		for(int i = 0; i< splitted.length;i++ )
		{
			for (int j = 0; j < splitted[i].length; j++) 
			{
				System.out.print(splitted[i][j]+" ");
			}
			System.out.println();
		}
		
		
	}
	
	
	
	public static boolean verif_padd(byte[] mess, short blockSize)
	{
		short padding = mess[mess.length- 1];
		for(int i = mess.length - padding; i< mess.length;i++ )
		{
			if(mess[i] != padding)
			{return false;}	
		}
		return true;		
	}

	
	public static byte[] pad(byte[] mess, short blockSize)
	{
		byte[] padded = new byte[mess.length + blockSize -  (mess.length % blockSize)];
		//copy of the original message into padded 
		for(int i =0; i < mess.length; i++)
		{
			padded[i] = mess[i];
		}
		//padding of the message according to pkcs7
		if(mess.length % blockSize == 0)
		{	
			//if the last block is full, we create another full block 
			for(int i = mess.length; i < mess.length +  blockSize ; i++)
			{
				
				padded[i] = (byte)  blockSize;
			}
		}
		else
		{
			//we fill the last block with the required number of bytes
			for(int i =mess.length; i < mess.length + blockSize -  (mess.length % blockSize); i++)
			{
				
				padded[i] = (byte) (blockSize - mess.length  % blockSize);
			}
			
		}
		return padded;
		
	}	
	
	public static byte[] extractMAC(byte[] msg)
	{
		byte[] MAC = new byte[CryptoTools.MAC_LENGTH];
		System.out.println("lg = " + msg.length);
		System.arraycopy(msg, msg.length - CryptoTools.MAC_LENGTH, MAC, 0, CryptoTools.MAC_LENGTH);
		return MAC;		
		
	}
	
	
	
	public static byte[] unpad(byte[] pad, short blockSize)
	{
				
		byte[] mess = new byte[pad.length - pad[pad.length-1]];
		
		for(int i =0; i < mess.length; i++)
		{
			mess[i] = pad[i];
		}		
		return mess;
	}
	

	
	public static byte[] ExtractLastBytes(byte[] buff, short lg)
	{
		byte[] output = new byte[lg];
		for(int i =0; i < buff.length; i++)
		{
			//System.out.println(buff[i]);
		}	
		
		System.arraycopy(buff, buff.length - lg, output, 0, lg);
		return output;			
	}
	
	public static byte[] ExtractFirstBytes(byte[] buff, short lg)
	{
		byte[] output = new byte[lg];
		for(int i =0; i < buff.length; i++)
			
		
		System.arraycopy(buff, 0, output, 0, lg);
		return output;			
	}
	
	
	public static  byte[] RandomArray(short lg)
	{
		Random rng = new Random();
	    byte[] iv1 = new byte[lg];
	    rng.nextBytes(iv1);	    
		return iv1;		
	}
	
	public static byte[] concat(byte[] A, byte[] B) 
	{
		   int aLen = A.length;
		   int bLen = B.length;
		   byte[] C= new byte[aLen+bLen];
		   System.arraycopy(A, 0, C, 0, aLen);
		   System.arraycopy(B, 0, C, aLen, bLen);
		   return C;
	}
	
	public static byte[][] split(byte[] source, short max_length)
	{
		int nb_arrays =  1 + (source.length / max_length); 
		int length_last_array = (source.length % max_length);
		
		byte[][] output = new byte[nb_arrays][];
		int i;
		for(i = 0;i<nb_arrays-1;i++)
		{
			output[i] = new byte[max_length];
			System.arraycopy(source,i*max_length, output[i],0,max_length);
		}
		output[i] = new byte[length_last_array];
		System.arraycopy(source,i*max_length, output[i],0,length_last_array);
		
		return output;	
	}
	
	
}
