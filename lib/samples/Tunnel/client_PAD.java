/* Author : Romain Pignard */

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class client_PAD {
	/* Constantes */
	public static final byte CLA_MONAPPLET = (byte) 0xB0;

	private static final short IV_LENGTH = 16;
	private static final short AES_BLOCK_LENGTH = 16;
	private  final static SecretKey shared_key = new SecretKeySpec(new byte[]{10,1,1,5,9,6,5,4,5,9,6,6,6,9,2,6}, "AES");

	public static byte[] APPLET_AID= { (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x00, (byte)0x09};

	private static Cipher cipher;

	
		
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
	
	public static byte[] unpad(byte[] pad, short blockSize)
	{
		//System.out.println(pad.length);
		//System.out.println(pad[pad.length-1]);		
		byte[] mess = new byte[pad.length - pad[pad.length-1]];
		//System.out.println(mess.length);
		for(int i =0; i < mess.length; i++)
		{
			mess[i] = pad[i];
		}
		
		return mess;
	}
	
	private void createTunnel(Cipher ciff, CardChannel carte)
	{
		
		
		
	}
	
	private static SecretKey extractKey(byte[] received_data, short blockSize, short keyLength, short secret)
	{
		// suppression du padding
		byte[] unpadded = unpad(received_data,blockSize);
		
		// test si le retour contient le secret
		if(unpadded[unpadded.length - 1] == secret)
		{
		//	System.out.println("réussite");
			// copie de la valeur de la nouvelle cle 
			byte[] cle = new byte[keyLength];
			
			
			System.arraycopy(unpadded, 0, cle, 0, keyLength);
			
			for(int i= 0; i < cle.length;i++)
			{	
			//System.out.print((short) (cle[i] & 0xFF) + " ");
			}
			//System.out.println();
			return new SecretKeySpec(cle, "AES");
			 	 
		}	
		System.out.println("échec");
		return null;		
	}
	
	
	
	public static byte[] concat(byte[] A, byte[] B) {
		   int aLen = A.length;
		   int bLen = B.length;
		   byte[] C= new byte[aLen+bLen];
		   System.arraycopy(A, 0, C, 0, aLen);
		   System.arraycopy(B, 0, C, aLen, bLen);
		   return C;
		}
	
	private static  byte[] RandomArray(short lg)
	{
		Random rng = new Random();
	    byte[] iv1 = new byte[lg];
	    rng.nextBytes(iv1);
		return iv1;		
	}
	
	private static byte[] HelloClient(short secret) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		// IV du message
		byte[] iv = RandomArray(IV_LENGTH);
		
		// Premier bloc sans données significatives
		byte[] garbage = RandomArray(AES_BLOCK_LENGTH);
		
		for(int i= 0; i < garbage.length;i++)
		{	
		//System.out.print((short) (garbage[i] & 0xFF) + " ");
		}
		System.out.println();
		
		// Objet de chiffrement
		Cipher cipher2 = Cipher.getInstance("AES/CBC/NoPadding");	        
        cipher2.init(Cipher.ENCRYPT_MODE, shared_key, new IvParameterSpec(iv));					
       
		byte[] padded = pad(new byte[]{(byte) secret},AES_BLOCK_LENGTH);
		for(int i= 0; i < padded.length;i++)
		{	
			System.out.print((short) (padded[i] & 0xFF) + " ");
		}
		//System.out.println();
		
		return concat(iv,cipher2.doFinal(padded));
		
	}
	
	
	
	
	private static byte[] encrypt_with_IV(Cipher c, byte[] toCrypt, SecretKey k) 
			throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		// padding des données d'entree
		byte[] padded_data = pad(toCrypt, AES_BLOCK_LENGTH);
		//System.out.println();
		 for(int i= 0; i < padded_data.length;i++)
			{	
		//	System.out.print((short) (padded_data[i] & 0xFF) + " ");
			}
		// System.out.println();
		//génération de l'IV
		byte[] iv = RandomArray(IV_LENGTH);
		
		 for(int i= 0; i < iv.length;i++)
		{	
	//	System.out.print((short) (iv[i] & 0xFF) + " ");
		}
		//System.out.println();
		
		
		c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));		
		byte[] encrypted = c.doFinal(padded_data);
		return concat(iv,encrypted);		
	}
	private static byte[] decrypt_with_IV(Cipher c, byte[] toDecrypt, SecretKey k) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
	{
		
		byte[] iv = new byte[16];
		byte[] woIV = new byte[toDecrypt.length - 16];
		System.arraycopy(toDecrypt, 0, iv, 0, 16);
		System.arraycopy(toDecrypt, 16, woIV, 0,toDecrypt.length - 16);
		c.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(iv));		
		byte[] decrypted = c.doFinal(woIV);			
		
		
		return decrypted;
	}
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
	        ResponseAPDU r;
	      // byte[] crypted =  testCode();
	        
		/* Connexion au lecteur */
		TerminalFactory factory = TerminalFactory.getDefault();
		List<CardTerminal> terminals;
		try {
			terminals = factory.terminals().list();

			System.out.println("Terminaux : "+terminals);

			CardTerminal terminal = terminals.get(0);

			/* Connexion à la carte */
			Card card = terminal.connect("T=1");
			System.out.println("Carte : "+card);

			CardChannel channel = card.getBasicChannel();

			/* Sélection de l'applet */
			r = channel.transmit(new CommandAPDU((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, APPLET_AID));
			if (r.getSW() != 0x9000) {
				System.out.println("Erreur lors de la sélection de l'applet");
				System.exit(1);
			}

			/* Menu principal */
			boolean fin = false;
			SecretKey cle = null;
			//while (!fin) 
			{
				System.out.println();
				System.out.println("Application cliente Javacard");
				System.out.println("----------------------------");	
				System.out.println("1 - Etablissement de la clé de session");
				System.out.println("2 - Envoi de données chiffrées");
				System.out.println("3 - Envoi de données claires");					
				System.out.println("----------------------------");	
				System.out.println("Votre choix ?");

				
			
				
				// Scanner in = new Scanner(System.in); 
			    //   System.out.printf("Enter i Value:  ");
			      // int choix = in.nextInt();
			     int  choix = 1;
			
			      
			       switch (choix) {
			       case 1:
			    	   int compteur = 0;
			    	   while(compteur < 10000){
			    		  compteur++;
			    		 // System.out.println(compteur);
				       // mise en place de la clé de session
			    	//	byte [] hello =   HelloClient((short) 42);
				       r = channel.transmit(new CommandAPDU((byte)0xB0, 0x02, 0, 0));
						if (r.getSW() != 0x9000) {
							System.out.println("Erreur : status word different de 0x9000 "  + r.getSW());
						} else {						
							// byte[] recue = unpad(r.getData(),AES_BLOCK_LENGTH);
							byte[] recue = r.getData();
						//	System.out.println("donnees recues");
							for(int i= 0; i < recue.length;i++)
							{	
						//	System.out.println(i+" = "+ (recue[i] & 0xFF));
							}
						}
						// Test déchiffrement						
						
						
						byte[] iv2 = new byte[16];
						byte[] donnee = new byte[32];
						//System.out.println("Pas bien : status word different de 0x9000"  + r.getSW());
						System.arraycopy(r.getData(), 0, iv2, 0, 16);
						System.arraycopy(r.getData(), 16, donnee, 0, 32);
						
						Cipher cipher2 = Cipher.getInstance("AES/CBC/NoPadding");	        
				        cipher2.init(Cipher.DECRYPT_MODE, shared_key, new IvParameterSpec(iv2));					
				        byte[] data2;
						data2 =  cipher2.doFinal(donnee);
					//	System.out.println("donnees recues");
						for(int i= 0; i < data2.length;i++){
						
					//	  System.out.println(data2[i]);						 
						 
						}
						
						
						// réglage de la clé de session
						cle = extractKey(data2, AES_BLOCK_LENGTH, AES_BLOCK_LENGTH, (short) 42);
						if (cle == null)
						{System.out.println("faaaail");}	
						cipher = Cipher.getInstance("AES/CBC/NoPadding");
						
						
						
						
						byte[] a_chiffrer = pad(new byte[]{42},AES_BLOCK_LENGTH);
						byte[] iv3 = RandomArray(IV_LENGTH);
						
						for(int i= 0; i < a_chiffrer.length;i++){
							
							 // System.out.print((a_chiffrer[i] & 0xFF)+ " ");		 
								 
						}
						//System.out.println();
						
						cipher.init(Cipher.ENCRYPT_MODE, cle, new IvParameterSpec(iv3));
						byte[] a_envoyer = cipher.doFinal(a_chiffrer);
						byte[] pdu = concat(iv3,a_envoyer) ;
						System.out.println("lg = "+pdu.length );
						r = channel.transmit(new CommandAPDU((byte)0xB0, 0x04, a_envoyer.length , 0,pdu ));
						if (r.getSW() != 0x9000) {
							System.out.println("Erreur : status word different de 0x9000 "  + r.getSW());
						} else {
							
							
							 for(int i= 0; i < r.getData().length;i++){
									
								  System.out.print((r.getData()[i] & 0xFF)+ " ");		 
									 
									}
							System.out.println();
							
							
						}
			    	   }break;
			       	case 2:
			    	 // envoi de données
			    	   
			    	 //réglage des données à envoyer  
			    	byte[] donnees = new byte[]{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,17};
			    	// System.out.println(cle.getAlgorithm());
			    	byte [] crypted = encrypt_with_IV(cipher, donnees, cle);
			    	
			    	 
			    	 
			    	 
			    	 
			    	 
			    	  //envoi de l'APDU 
			    	 r = channel.transmit(new CommandAPDU((byte)0xB0, 0x01, crypted.length- IV_LENGTH, (byte) 0,crypted));			    	 
			    	 for(int i= 0; i < r.getData().length;i++){
							
					//	  System.out.print((r.getData()[i] & 0xFF)+ " ");				 
						 
						}	
			    	 /*
			    	byte[]  unpadded = (byte[]) unpad(r.getData(),AES_BLOCK_LENGTH);
			    	 for(int i= 0; i < unpadded.length;i++){
							
					  System.out.print((unpadded[i] & 0xFF)+ " ");		 
						 
						}	*/	    	 
			       } 

			}

			/* Mise hors tension de la carte */
			card.disconnect(false);

		} catch (CardException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	

		
	}
}
