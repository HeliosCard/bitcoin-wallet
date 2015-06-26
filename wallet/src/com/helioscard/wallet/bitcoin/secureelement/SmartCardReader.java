package com.helioscard.wallet.bitcoin.secureelement;

import java.io.IOException;

public interface SmartCardReader {
	public byte[] exchangeAPDU(byte[] commandAPDU) throws IOException;
	public void close();
	public boolean checkConnection();
}
