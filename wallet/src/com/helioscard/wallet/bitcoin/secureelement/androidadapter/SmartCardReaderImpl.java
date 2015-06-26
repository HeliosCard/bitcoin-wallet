package com.helioscard.wallet.bitcoin.secureelement.androidadapter;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;

import com.helioscard.wallet.bitcoin.secureelement.SmartCardReader;

public class SmartCardReaderImpl implements SmartCardReader {
	private boolean _connectionAttempted = false;
	
	private static Logger _logger = LoggerFactory.getLogger(SmartCardReaderImpl.class);
	
	// private Tag _tag;
	private IsoDep _isoDep;
	
	public SmartCardReaderImpl(Tag tag) throws IOException {
		// _tag = tag;
		_isoDep = IsoDep.get(tag);
		_isoDep.setTimeout(50000); // set a long timeout so we have time for long operations like keygen
	}
	
	public byte[] exchangeAPDU(byte[] commandAPDU) throws IOException {
		return _isoDep.transceive(commandAPDU);
	}
	
	public void close() {
		try {
			_isoDep.close();
		} catch (IOException e) {
			// nothing much we can do here
			_logger.info("Exception closing isoDep connection: " + e.toString());
		}
	}

	@Override
	public boolean checkConnection() {
		if (!_connectionAttempted) {
			// we haven't tried connecting yet, try connecting now
			try {
				_connectionAttempted = true;
				if (!_isoDep.isConnected()) {
					_isoDep.connect();					
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				_logger.info("checkConnection: IOException" + e.toString());
			}
		}

		return _isoDep.isConnected();
	}
}
