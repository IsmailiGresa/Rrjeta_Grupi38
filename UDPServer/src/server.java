import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Socket;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class server {
	
	public static final int KEY_SIZE = 1024;
	private static SecretKey DESSecretKey;
	private static byte[] DESKey;
	private static byte[] rndIV;
	public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeySpecException, JSONException
	{
		
		DatagramSocket sock = null;
		try
		{
			//1. creating a server socket, parameter is local port number
			sock = new DatagramSocket(7777);
	
			//buffer to receive incoming data
			byte[] buffer = new byte[65536];
			DatagramPacket incoming = new DatagramPacket(buffer, buffer.length);
			
			//2. Wait for an incoming data
			echo("Server socket created. Waiting for incoming data...");
			
			//communication loop
			while(true)
			{
				sock.receive(incoming);
				byte[] data = incoming.getData();
				String s = new String(data, 0, incoming.getLength());
				
				String [] userData = s.split(" ");
				//System.out.println("Command: " + userData[0]);
				//System.out.println("Username: " + userData[1]);
				//System.out.println("Password: " + userData[2]);
				
				if(userData[0].equals("create-user")) {

					String user1 = userData[1];
					String password = userData[2];
					Security.addProvider(new BouncyCastleProvider());
	            	File f = new File("keys/" + user1 + ".json");
        			File file1 = new File("C:/Users/IFES Yoga/Desktop/User/data/" + user1 + ".json");
            		File file = new File("C:/Users/IFES Yoga/Desktop/User/data/" + user1 + ".password.json");
            		if(file1.exists()) {
            			System.out.println("ERROR: User already exists");
            		} else {
            		FileWriter myWriter1 = new FileWriter(file1);
		    		FileWriter myWriter = new FileWriter(file);
		    		SecureRandom random = new SecureRandom();
		    		byte[] salt = new byte[16];
		    		random.nextBytes(salt);
		    		String password2 = new String(salt).concat(password);
		    		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
		    		SecretKeyFactory f1 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		    		byte[] hash = f1.generateSecret(spec).getEncoded();
		    		Base64.Encoder enc = Base64.getEncoder();
		    		String hashpw = enc.encodeToString(hash);
		    		String saltpw =enc.encodeToString(password2.getBytes());
		    		myWriter1.write(user1);
		    		myWriter1.close();
		    		myWriter.write(hashpw + " . " +enc.encodeToString(salt)+" . "+saltpw);
		    	    myWriter.close();
		    	    
		    	    System.out.println("OK: User has been created");
				} }
				else if(userData[0].equals("login")){ 
					
					String user1 = userData[1];
					String password = userData[2];
					String id = userData[3];
					String name = userData[4];
					String year = userData[5];
					String month = userData[6];
					String value = userData[7];
					String type = userData[8];
					
					
					File file1 = new File("C:/Users/IFES Yoga/Desktop/User/data/" + user1 + ".password.json");
					String cipher = readLine(file1.toString());
					String messageSplit[] = cipher.split(" . ");
					Base64.Encoder enc = Base64.getEncoder();
					byte[] decodedsalt = Base64.getDecoder().decode(messageSplit[1]);
					String filepw = messageSplit[2];
					filepw= filepw.replaceAll("[\\n]", "");
					if(file1.exists()) {
						System.out.println("OK: User has logged in");
						ArrayList<user> array = new ArrayList<user>();
				        for(int i = 0 ; i < 1; i++){
				            array.add(new user(Integer.toString(i), user1, Integer.toString(i+100), Integer.toString(2022), Integer.toString(04), Integer.toString(i)));
				        }
						 JSONArray jsonArray = new JSONArray();
					        for (int i = 0;i < array.size() ; i++) {
					            JSONObject obj = new JSONObject();
					            JSONObject objItem =  new JSONObject();
					            objItem.put("id", array.get(i).getId());
					            objItem.put("name",  array.get(i).getName());
					            objItem.put("year", array.get(i).getYear());
					            objItem.put("month", array.get(i).getMonth());
					            objItem.put("value", array.get(i).getValue());
					            objItem.put("type", array.get(i).getType());
					            obj.put(user1, objItem);
					            jsonArray.put(obj);
						try (FileWriter file = new FileWriter("C:/Users/IFES Yoga/Desktop/User/data/" + user1 + ".json")) {
				            file.write(jsonArray.toString());
//				            System.out.println("Successfully Copied JSON Object to File...");
				           System.out.println("\nJSON Object: " + jsonArray);
				        } catch(Exception e){
				            System.out.println(e);
				        	}
					}}else {
						System.out.println("ERROR: User does not exist");
					}
				} else {
						System.out.println("ERROR: Wrong command name! ");
				}
				//echo the details of incoming data - client ip : client port - client message
				//echo(incoming.getAddress().getHostAddress() + " : " + incoming.getPort() + " - " + s);
				
				//s = "OK: " + s;
				
				DatagramPacket dp = new DatagramPacket(s.getBytes() , s.getBytes().length , incoming.getAddress() , incoming.getPort());
				sock.send(dp);
			}
		}
		catch(IOException e)
		{
			System.err.println("IOException " + e);
		}
	}

	//simple function to echo data to terminal
	public static void echo(String msg)
	{
		System.out.println(msg);
	}
	private static PublicKey getpubKeyFromFile(String username)
			throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, URISyntaxException {
		try {
			String filePath = "keys/" + username + ".pub.xml";
			String keypub = readLine(filePath);
			PemObject pem = new PemReader(new StringReader(keypub)).readPemObject();
			byte[] pubKeyBytes = pem.getContent();
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
			RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
				return pubKey;
		}catch (Exception e) {
		}	
		return null;
	}

	private static RSAPrivateKey getprivKeyFromFile(String decodedUser)
			throws NoSuchAlgorithmException, IOException, URISyntaxException, InvalidKeySpecException {

		String filePath = "keys/" + decodedUser + ".xml";

		RSAPrivateKey privKey = (RSAPrivateKey) PemUtils1.readPrivateKeyFromFile(filePath, "RSA");
		return privKey;
	}
	
	private static void writePemFile(Key key, String description, String filename)
			throws FileNotFoundException, IOException {
		
		PemFile1 pemFile = new PemFile1(key, description);
		pemFile.write(filename);
		//LOGGER.info(String.format("%s successfully writen in file %s.", description, filename));
	}
	
//	private static boolean checkpassword(String username) {
//		
//		String loginData = "";
//		String password1 = "";
//		String rptpassword2 = "";
//		
//		Scanner input = new Scanner(System.in);
//		File file1 = new File("C:/Users/IFES Yoga/Desktop/User/keys/" + username + ".password.json");
//		boolean same = false;
//		if(file1.exists()) {
//            System.out.print("Password: ");
//            password1 = input.nextLine();
//            input.close();
//            String cipher = readLine(file1.toString());
//			String messageSplit[] = cipher.split(" . ");
//			Base64.Encoder enc = Base64.getEncoder();
//			byte[] decodedsalt = Base64.getDecoder().decode(messageSplit[1]);
//			String filepw = messageSplit[2];
//			filepw= filepw.replaceAll("[\\n]", "");
//			String password2=new String(decodedsalt).concat(password1);
//			password2 =  enc.encodeToString(password2.getBytes());
//			if(password2.equals(filepw)) {
//				System.out.println("Correct");
//				same = true;
//			}else {
//				System.out.println("Incorrect");
//			}}else {
//				System.out.println("User does not exist");
//			}
//			return same;
//	}	

	private static byte[] generateIV() {

		SecureRandom random = new SecureRandom();
		byte iv[] = new byte[8]; // generate random 8 byte IV.
		random.nextBytes(iv);
		client.rndIV = iv;
		return client.rndIV;
	}

	private static String base64IV() {
		
		return Base64.getEncoder().encodeToString(generateIV());
	}
	
	public static String encryptRSA(byte[] iv, PublicKey publicKey) throws Exception {

		Cipher encryptCipher = Cipher.getInstance("RSA/CBC/PKCS1Padding");
		encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return Base64.getEncoder().encodeToString(iv);
	}

	public static String encryptRSAText (String s, PublicKey publicKey) 
			throws IOException, GeneralSecurityException {
        
		Cipher cipher = Cipher.getInstance ("RSA/CBC/PKCS1Padding");
        cipher.init (Cipher.ENCRYPT_MODE, publicKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal (s.getBytes ("UTF-8")));
    }
	
	public static byte[] decryptRSAText (String s, PrivateKey privateKey) 
			throws IOException, GeneralSecurityException {
        
		Cipher cipher = Cipher.getInstance ("RSA/CBC/PKCS1Padding");
        cipher.init (Cipher.DECRYPT_MODE, privateKey);
        return (cipher.doFinal (Base64.getDecoder().decode(s)));
    }
	
	public static boolean verify(String s, String signature, PublicKey publicKey) throws Exception {
	    Signature publicSignature = Signature.getInstance("SHA256withRSA");
	    try {
	    	try {
	    publicSignature.initVerify(publicKey);
	    publicSignature.update(s.getBytes());
	    	}catch (InvalidKeyException e) {
				System.out.println("\nNo Public Key.");
			}
	    byte[] signatureBytes = Base64.getDecoder().decode(signature);

	    return publicSignature.verify(signatureBytes);
	}catch(IllegalArgumentException e){
		return false;
	}}
	
	private static void getDESkey(String username)
			throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, URISyntaxException, Exception {

		byte[] decodedKey = Base64.getDecoder().decode(encryptRSA(client.rndIV, getpubKeyFromFile(username)));
		client.DESKey = decodedKey;
	}

	private static void getSecretDES() {
		SecretKey originalKey = new SecretKeySpec(client.DESKey, 0, client.DESKey.length, "DES");
		client.DESSecretKey = originalKey;
	}

	private static String encryptDes(String username, String s)
			throws InvalidKeySpecException, IOException, URISyntaxException, Exception {
		getDESkey(username);
		getSecretDES();
		Cipher desCipher;
		
		s = encryptRSAText(s, getpubKeyFromFile(username));
		// Create the cipher
		desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

		// Initialize the cipher for encryption
		desCipher.init(Cipher.ENCRYPT_MODE, DESSecretKey);

		// sensitive information
		byte[] text = s.getBytes();
		// Encrypt the text
		byte[] textEncrypted = desCipher.doFinal(text);

		return Base64.getEncoder().encodeToString(textEncrypted).toString();
	}
	
	private static String writeMessage(String username, String message)
			throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, URISyntaxException, Exception {
		
		
		return (base64IV() + " . " + encryptRSA(client.rndIV, getpubKeyFromFile(username))
				+ " . " + encryptDes(username, message));
	}
	
	private static String readLine(String filePath) {
		
		final StringBuilder contentBuilder = new StringBuilder();
		try (Stream<String> stream = Files.lines(Paths.get(filePath), StandardCharsets.UTF_8)) {
			stream.forEach(s -> contentBuilder.append(s).append("\n"));
		} catch (IOException e) {
		}
		return contentBuilder.toString();
	}
}
