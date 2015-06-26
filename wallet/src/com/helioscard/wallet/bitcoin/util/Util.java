package com.helioscard.wallet.bitcoin.util;

import java.nio.ByteBuffer;

public class Util {
    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes, int fromIndex, int numBytes) {
        char[] hexChars = new char[numBytes * 2];
        for (int j = fromIndex; j < numBytes; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, 0, bytes.length);
    }

    // TODO: remove this, just for testing
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len/2];

        for(int i = 0; i < len; i+=2){
            data[i/2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }

        return data;
    }
    
	public static long bytesToLong(byte[] bytes) {
		return bytesToLong(bytes, 0, bytes.length);
	}
	
	public static long bytesToLong(byte[] bytes, int offset, int length) {
	    ByteBuffer buffer = ByteBuffer.allocate(8);
	    buffer.put(bytes, offset, length);
	    buffer.flip(); //need flip 
	    return buffer.getLong();
	}

	public static short bytesToShort(byte[] bytes, int offset, int length) {
		ByteBuffer buffer = ByteBuffer.allocate(2);
		buffer.put(bytes, offset, length);
		buffer.flip(); //need flip
		return buffer.getShort();
	}

	public static byte[] longToBytes(long incomingLong) {
	    ByteBuffer buffer = ByteBuffer.allocate(8);
	    buffer.putLong(incomingLong);
	    return buffer.array();
	}
	
	public static int bytesToInt(byte[] bytes) {
	    ByteBuffer buffer = ByteBuffer.allocate(4);
	    buffer.put(bytes);
	    buffer.flip(); //need flip 
	    return buffer.getInt();		
	}

	public static byte[] intToBytes(int incomingInt) {
	    ByteBuffer buffer = ByteBuffer.allocate(4);
	    buffer.putInt(incomingInt);
	    return buffer.array();
	}
}
