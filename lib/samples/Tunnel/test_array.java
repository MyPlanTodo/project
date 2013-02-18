/* Author : Romain Pignard */

public class test_array {

	
	public static void main(String[] args)
	{
		byte[] a_tester =  ArrayTools.RandomArray((short) 509);
		byte[][] output = ArrayTools.split(a_tester, (short) 64);
		for(int i =0; i < output.length; i++)
		{
			/*System.out.println();
			for(int j = 0;j < output[i].length; j++)
			{
				System.out.print(" " + output[i][j]);
			}	
			*/			
		}	
		
		a_tester = ArrayTools.RandomArray((short) 64);
		byte[] out  = ArrayTools.pad(a_tester, (short) 80);
		ArrayTools.printByteArray(out, (short) 16);
		
		
	}
	
	
	
	
}
