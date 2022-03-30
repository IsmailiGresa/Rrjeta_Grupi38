import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.json.JSONArray;
import org.json.JSONObject;


public class client{
	
	protected final static Logger LOGGER = Logger.getLogger(client.class);
	public static final int KEY_SIZE = 1024;
	
	public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, URISyntaxException{
		DatagramSocket sock = null;
		int port = 7777;
		String s;
		BufferedReader cin = new BufferedReader(new InputStreamReader(System.in));
		try
		{
			sock = new DatagramSocket();
			InetAddress host = InetAddress.getByName("localhost");
			while(true)
			{
				//take input and send the packet
				System.out.println("Enter command: ");
				s = (String)cin.readLine();
				byte[] b = s.getBytes();
				if(s.equals("create-user")) {
					createUser(s);
				}
					else if(s.equals("login")){ 
					login(s);
				} else if(s.equals("expenses")) {
					expenses(s);
				}
				else {
						System.out.println("Wrong command name! ");
					}
				DatagramPacket  dp = new DatagramPacket(b , b.length , host , port);
				sock.send(dp);
				
				//now receive reply
				//buffer to receive incoming data
				byte[] buffer = new byte[65536];
				DatagramPacket reply = new DatagramPacket(buffer, buffer.length);
				sock.receive(reply);
				
				byte[] data = reply.getData();
				s = new String(data, 0, reply.getLength());
				
				//echo the details of incoming data - client ip : client port - client message
				System.out.println(reply.getAddress().getHostAddress() + " : " + reply.getPort() + " - " + s);
			}
		}
		catch(IOException e)
		{
			System.err.println("IOException " + e);
		}
	}

	private static void createUser(String username)
			throws FileNotFoundException, IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		
		Scanner input = new Scanner(System.in);
		        String password, rptpassword;
		        System.out.print("Username: ");
		        username = input.next();
		            System.out.print("Password: ");
		            password = input.next();
		            String regex = "((?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{6,})";
		            Pattern pattern = Pattern.compile(regex);
		            Matcher matcher = pattern.matcher(password);
		            if(matcher.matches()) {
		            	System.out.print("Confirm Password: ");
			            rptpassword = input.next();
			            input.close();
		            	if (password.equals(rptpassword)) {
			            	System.out.println("User "+ username +" has been created.");
			            	}
		            	Security.addProvider(new BouncyCastleProvider());
	            		File f = new File("keys/" + username + ".xml");
	            		if (f.exists()) {
	            			System.out.println("User's RSA KEY Exists");
	            		} else {
	            		KeyPair keyPair = generateRSAKeyPair();
	            		RSAPrivateKey priv = (RSAPrivateKey) keyPair.getPrivate();
	            		RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();

	            		writePemFile(priv, "RSA PRIVATE KEY", "keys/" + username + ".xml");
	            		writePemFile(pub, "RSA PUBLIC KEY", "keys/" + username + ".pub.xml");
	            	}
		            			File file1 = new File("C:/Users/IFES Yoga/Desktop/User/keys/" + username + ".json");
			            		File file = new File("C:/Users/IFES Yoga/Desktop/User/keys/" + username + ".password.json");
			            		FileWriter myWriter1 = new FileWriter(file1);
					    		FileWriter myWriter = new FileWriter(file);
					    		SecureRandom random = new SecureRandom();
					    		byte[] salt = new byte[16];
					    		random.nextBytes(salt);
					    		String password2=new String(salt).concat(password);
					    		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
					    		SecretKeyFactory f1 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
					    		byte[] hash = f1.generateSecret(spec).getEncoded();
					    		Base64.Encoder enc = Base64.getEncoder();
					    		String hashpw = enc.encodeToString(hash);
					    		String saltpw =enc.encodeToString(password2.getBytes());
					    		myWriter1.write(username);
					    		myWriter1.close();
					    		myWriter.write(hashpw + " . " +enc.encodeToString(salt)+" . "+saltpw);
					    	    myWriter.close();
					    	    System.out.println("Successfully created the hashed password.");
			            		}else {
			            		System.out.println("Passwords do not match. Please try again.");
			            		}
			            	        
			            }   

	private static void login(String username) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, URISyntaxException {
		
		File file1 = new File("C:\\Users\\IFES Yoga\\Desktop\\User/keys/" + username + ".json");
		
		Scanner input = new Scanner(System.in);
	    String username1;
	    	System.out.print("Username: ");
	    	username1 = input.nextLine();
	    	File file2 = new File("C:\\Users\\IFES Yoga\\Desktop\\User/keys/" + username1 + ".json");
	    	if(file2.equals(file1)) {
	    		if(checkpassword(username)) {
		    		RSAPublicKey publicKey = (RSAPublicKey) getpubKeyFromFile(username);
		    		RSAPrivateKey privateKey = getprivKeyFromFile(username);
		    	}
	    	}else {
	    		System.out.println("User not found.");
	    	}
	    	}

	private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
		generator.initialize(KEY_SIZE);
		KeyPair keyPair = generator.generateKeyPair();
		return keyPair;
	}

	private static PublicKey getpubKeyFromFile(String username)
		throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, URISyntaxException {
	try {
	String filePath = "C:/Users/IFES Yoga/Desktop/User/" + username + ".pub.json";
	
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

	String filePath = "C:/Users/IFES Yoga/Desktop/User/keys/" + decodedUser + ".json";

	RSAPrivateKey privKey = (RSAPrivateKey) PemUtils1.readPrivateKeyFromFile(filePath, "RSA");
	return privKey;
}
	
	private static void writePemFile(Key key, String description, String filename)
			throws FileNotFoundException, IOException {
		PemFile1 pemFile = new PemFile1(key, description);
		pemFile.write(filename);

		LOGGER.info(String.format("%s successfully written in file %s.", description, filename));
	}

 
	private static void expenses(String username) {
		ArrayList<user> array = new ArrayList<user>();
        for(int i = 0 ; i < 100; i++){
            array.add(new user(i+"", i+"", i+"", i+"", i+"", i+"", i+"", i+""));
        }
        JSONArray jsonArray = new JSONArray();
        for (int i = 0;i < array.size() ; i++) {
            JSONObject obj = new JSONObject();
            JSONObject objItem =  new JSONObject();
            objItem.put("id", array.get(i).getId());
            objItem.put("name",  array.get(i).getName());
            objItem.put("lastname",  array.get(i).getLastname());
            objItem.put("bill", array.get(i).getBill());
            objItem.put("year", array.get(i).getYear());
            objItem.put("month", array.get(i).getMonth());
            objItem.put("value", array.get(i).getValue());
            objItem.put("type", array.get(i).getType());
            obj.put("user", objItem);
            jsonArray.put(obj);
        }
        try (FileWriter file = new FileWriter("C:/Users/IFES Yoga/Desktop/User/keys/" + username + ".json")) {
            file.write(jsonArray.toString());
            System.out.println("Successfully Copied JSON Object to File...");
            System.out.println("\nJSON Object: " + jsonArray);
        } catch(Exception e){
            System.out.println(e);
        	}
        }
	
	private static boolean checkpassword(String username) {
		
    	File file = new File("C:\\Users\\IFES Yoga\\Desktop\\User/keys/" + username + ".password.json");
	
    	Scanner input = new Scanner(System.in);
        String password1;
        boolean same = false;
            System.out.print("Password: ");
            password1 = input.nextLine();
            input.close();
            String cipher = readLine(file.toString());
			String messageSplit[] = cipher.split(" . ");
			Base64.Encoder enc = Base64.getEncoder();
			byte[] decodedsalt = Base64.getDecoder().decode(messageSplit[1]);
			
			String filepw = messageSplit[2];
			filepw= filepw.replaceAll("[\\n]", "");
			String password2=new String(decodedsalt).concat(password1);
			password2 =  enc.encodeToString(password2.getBytes());
		
			if(password2.equals(filepw)) {
				System.out.println("Correct");
				same = true;
			}else {
				System.out.println("Incorrect");
			}
			return same;
	}	
	
	private static String readLine(String filePath) {
		final StringBuilder contentBuilder = new StringBuilder();

		try (Stream<String> stream = Files.lines(Paths.get(filePath), StandardCharsets.UTF_8)) {
			stream.forEach(s -> contentBuilder.append(s).append("\n"));
		} catch (IOException e) {
		}

		return contentBuilder.toString();
	}
	//simple function to echo data to terminal
	
}
	