package com.helioscard.wallet.bitcoin.secureelement;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helioscard.wallet.bitcoin.util.Util;

public class ECKeyEntry {
	private boolean _isLocked;
	private byte[] _publicKeyBytes;
	private byte[] _privateKeyBytes;
	private String _friendlyName;
	private long _timeOfKeyCreationMillisSinceEpoch;
	private byte[] _originalAssociatedData;
	
	public static final int ASSOCIATED_DATA_TYPE_VERSION = 1;
	public static final int ASSOCIATED_DATA_TYPE_FRIENDLY_NAME = 2;
	public static final int ASSOCIATED_DATA_TYPE_GENERATION_TIME = 3;
	public static final int ASSOCIATED_DATA_TYPE_MISC_BIT_FIELD = 4;

	private static Logger _logger = LoggerFactory.getLogger(ECKeyEntry.class);
	
	private boolean _isPublicKeyCompressed = false;
	
	public ECKeyEntry(boolean isLocked, byte[] publicKeyBytes, byte[] associatedData, byte[] privateKeyBytes) {
		_isLocked = isLocked;
		_publicKeyBytes = publicKeyBytes;
		_privateKeyBytes = privateKeyBytes;
		
		// decode the associated data
		if (associatedData != null) {
			decodeAssociatedData(associatedData);
		}
	}
	
	private void decodeAssociatedData(byte[] associatedData) {
		_originalAssociatedData = associatedData;
		ByteArrayInputStream stream = new ByteArrayInputStream(associatedData);
		try {
			while (stream.available() > 0) {
				int fieldType = stream.read();
				if (fieldType == -1 || fieldType == 0) {
					// reached end of stream
					return;
				}
				int fieldLength = stream.read();
				if (fieldLength == -1) {
					// reached end of stream
					return;
				}
				if (fieldLength == 0) {
					// 0-length field?
					_logger.info("decodeAssociatedData: read 0 length field");
					continue;
				}
				byte[] fieldData = new byte[fieldLength];
				if (stream.read(fieldData, 0, fieldLength) == -1) {
					_logger.error("decodeAssociatedData: Field was missing bytes");
					return;
				}
				switch(fieldType) {
					case ASSOCIATED_DATA_TYPE_VERSION: {
						// ignore for now
						_logger.info("decodeAssociatedData: read version " + Util.bytesToHex(fieldData));
						break;
					}
					case ASSOCIATED_DATA_TYPE_FRIENDLY_NAME: {
						_friendlyName = new String(fieldData);
						_logger.info("decodeAssociatedData: read friendly name " + _friendlyName);
						break;
					}
					case ASSOCIATED_DATA_TYPE_GENERATION_TIME: {
						_timeOfKeyCreationMillisSinceEpoch = Util.bytesToLong(fieldData);
						_logger.info("decodeAssociatedData: read key generation time of " + _timeOfKeyCreationMillisSinceEpoch);
						break;
					}
					case ASSOCIATED_DATA_TYPE_MISC_BIT_FIELD: {
						_isPublicKeyCompressed = (fieldData[0] & 0x80) != 0;
						_logger.info("decodeAssociatedData: read key compression of " + (_isPublicKeyCompressed ? "true" : "false"));
						break;
					}
				}
			}
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				_logger.error("decodeAssociatedData: error closing stream: " + e.toString());
			}
		}
	}
	
	public byte[] getAssociatedData() {
		return _originalAssociatedData;
	}
	
	public byte[] getPublicKeyBytes() {
		// The key that we read from the smart card is always uncompressed
		// but now check if the way the key is used within the bitcoin system is compressed
		// or uncompressed (each form results in a different Bitcoin address).  Return the correct one.
		if (_isPublicKeyCompressed) {
			// return a compressed form of the public key
			return ECUtil.getPublicKeyBytesFromEncoding(_publicKeyBytes, true);
		} else {
			return _publicKeyBytes;
		}
	}
	
	public byte[] getPrivateKeyBytes() {
		return _privateKeyBytes;
	}
	
	public String getFriendlyName() {
		return _friendlyName;
	}
	
	public long getTimeOfKeyCreationSecondsSinceEpoch() {
		return _timeOfKeyCreationMillisSinceEpoch / 1000; // convert to seconds
	}
	
	@Override
	public void finalize() {
		if (_privateKeyBytes != null) {
			Arrays.fill(_privateKeyBytes, 0, _privateKeyBytes.length - 1, (byte)0);
		}
	}
}
