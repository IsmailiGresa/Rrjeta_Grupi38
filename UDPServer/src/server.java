import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

//import org.json.JSONArray;
//import org.json.JSONException;
//import org.json.JSONObject;


public class server {
	public static void main(String args[])
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
				
				//echo the details of incoming data - client ip : client port - client message
				echo(incoming.getAddress().getHostAddress() + " : " + incoming.getPort() + " - " + s);
				
				s = "OK : " + s;
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
	
//	private static void Store() throws JSONException {
//		
//        ArrayList<User> array = new ArrayList<User>();
//        for(int i = 0 ; i < 100; i++){
//            array.add(new User(i+"", i+"", i+"", i+"", i+"", i+"", i+"", i+""));
//        }
//        JSONArray jsonArray = new JSONArray();
//        for (int i = 0;i < array.size() ; i++) {
//            JSONObject obj = new JSONObject();
//            JSONObject objItem =  new JSONObject();
//            objItem.put("id", array.get(i).getId());
//            objItem.put("name",  array.get(i).getName());
//            objItem.put("lastname",  array.get(i).getLastname());
//            objItem.put("bill", array.get(i).getBill());
//            objItem.put("year", array.get(i).getYear());
//            objItem.put("month", array.get(i).getMonth());
//            objItem.put("value", array.get(i).getValue());
//            objItem.put("type", array.get(i).getType());
//            obj.put("user", objItem);
//            jsonArray.put(obj);
//        }
}