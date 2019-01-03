package model;

public class Util {

	public static String bytestoString(byte[] bytes) {
		StringBuilder st = new StringBuilder();	
		int i =0;
		for (byte b : bytes) {
			st.append(String.format("%02x", b & 0xff));
            if(++i %16 == 0)
            {
            	st.append("\n");    	
            }
		}
		return st.toString();

	}
}
