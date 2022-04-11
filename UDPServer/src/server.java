import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.stream.Stream;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import processing.xml.XMLElement;

public class server {
	
	public static void main(String args[]) throws NoSuchAlgorithmException, InvalidKeySpecException
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
	            	File f = new File("keys/" + user + ".json");
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
				else if(s.equals("login")){ 
					
					String user = userData[1];
					String password = userData[2];
					File file = new File("C:/Users/IFES Yoga/Desktop/User/data/" + user + ".json");
					File file1 = new File("C:/Users/IFES Yoga/Desktop/User/data/" + user + ".password.json");
					String cipher = readLine(file1.toString());
					String messageSplit[] = cipher.split(" . ");
					Base64.Encoder enc = Base64.getEncoder();
					byte[] decodedsalt = Base64.getDecoder().decode(messageSplit[1]);
					String filepw = messageSplit[2];
					filepw= filepw.replaceAll("[\\n]", "");
					if(password.equals(filepw)) {
						System.out.println("OK: User has logged in");
					}else {
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


	
	private static void createUser() {
		// TODO Auto-generated method stub
		
	}



	//simple function to echo data to terminal
	public static void echo(String msg)
	{
		System.out.println(msg);
	}
	
	public static void KeyGenerator() throws NoSuchAlgorithmException{
	      //Creating KeyPair generator object
	      KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DSA");
	      //Initializing the KeyPairGenerator
	      keyPairGen.initialize(2048);
	      //Generating the pair of keys
	      KeyPair pair = keyPairGen.generateKeyPair();
	      //Getting the public key from the key pair
	      PublicKey publicKey = pair.getPublic(); 
	      System.out.println("Keys generated");
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
