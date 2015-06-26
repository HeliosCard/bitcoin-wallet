package com.helioscard.wallet.bitcoin.secureelement.real;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Random;

import org.bitcoinj.core.Wallet;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.LazyECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;

import com.google.common.collect.ImmutableList;
import com.helioscard.wallet.bitcoin.secureelement.ECKeyEntry;
import com.helioscard.wallet.bitcoin.secureelement.ECUtil;
import com.helioscard.wallet.bitcoin.secureelement.PKCS5Util;
import com.helioscard.wallet.bitcoin.secureelement.SecureElementApplet;
import com.helioscard.wallet.bitcoin.secureelement.SmartCardReader;
import com.helioscard.wallet.bitcoin.secureelement.exception.CardWasWipedException;
import com.helioscard.wallet.bitcoin.secureelement.exception.KeyAlreadyExistsException;
import com.helioscard.wallet.bitcoin.secureelement.exception.SmartCardFullException;
import com.helioscard.wallet.bitcoin.secureelement.exception.WrongPasswordException;
import com.helioscard.wallet.bitcoin.secureelement.exception.WrongVersionException;
import com.helioscard.wallet.bitcoin.util.Util;

public class SecureElementAppletImpl extends SecureElementApplet {
	// internal state

	private static Logger _logger = LoggerFactory.getLogger(SecureElementAppletImpl.class);
	
	private static final int LENGTH_OF_PUBLIC_KEY = 65;
	private static final int LENGTH_OF_PRIVATE_KEY = 32;
	private static final int LENGTH_OF_ASSOCIATED_DATA = 64;

    private static final byte CARD_IDENTIFIER_LENGTH = 8;
	private static final short SEED_CREATION_TIME_SIZE = 8;
	private static final byte TRANSACTION_NUMBER_SIZE = 16;
    private static final byte PRE_COMPUTED_HASH_SIZE = 32;
    private static final byte ANTI_MALWARE_KEY_SIZE = 32;

	private enum SecureElementState {
	    DISCONNECTED, STATE_INFORMATION_READ
	}

	private SecureElementState _currentState = SecureElementState.DISCONNECTED;

	private SmartCardReader _smartCardReader;

    private String _cardIdentifier;
	private byte[] _version = new byte[2];
    private short _versionShort;
	private int _passwordAttemptsLeft;
	private PINState _pinState = PINState.NOT_SET;
	private boolean _loggedIn;
    private boolean _seedSet;
    private long _seedCreationTime;
	private int _maxNumberOfKeys;
	private int _currentNumberOfKeys;
	private long _timeOfAppletInstallation;
	private long _timeOfLastRefresh;
    private byte[] _transactionNumber;

	private static final int LENGTH_OF_PASSWORD_PKCS5_KEY_IN_BITS = 256;
	private static final int DEFAULT_ITERATION_COUNT = 20000;
	private int _passwordMetaDataVersion = -1;
	private static final int FIELD_PASSWORD_META_DATA_VERSION = 1;
	private static final int FIELD_PASSWORD_META_DATA_PKCS5_ITERATION_COUNT = 2;
	private static final int FIELD_PASSWORD_META_DATA_PKCS5_PASSWORD_KEY_SALT = 3;
	private static final int FIELD_PASSWORD_META_DATA_PKCS5_ENCRYPTION_KEY_SALT = 4;
	private int _passwordPKCS5IterationCount;
	private byte[] _passwordPKCS5PasswordKeySalt;
	private byte[] _passwordPKCS5EncryptionKeySalt;

	public SecureElementAppletImpl(SmartCardReader smartCardReader) {
		_smartCardReader = smartCardReader;
	}
	
	private void ensureInitialStateRead(boolean forced) throws IOException {
		if (!checkConnection()) {
			throw new IOException("Not connected.");
		}
		
		if (!forced && _currentState != SecureElementState.DISCONNECTED) {
			// we've already read in the initial state information
			_logger.info("ensureInitialStateRead: already read state information");
			return;
		}

		byte[] commandAPDU;
		if (_currentState == SecureElementState.DISCONNECTED) {
			// if we're not connected, we need to select the applet
			commandAPDU = new byte[] {0x00, (byte)0xa4, 0x04, 0x00, 0x0D, (byte)0xff, (byte)0x68, (byte)0x65, (byte)0x6c, (byte)0x69, (byte)0x6f, (byte)0x73, (byte)0x63, (byte)0x61, (byte)0x72, (byte)0x64, (byte)0x01, (byte)0x01, 0x00};
		} else {
			// otherwise the applet is already selected, just send get status command
			commandAPDU = new byte[] {(byte)0x80, 0x01, 0x00, 0x00, 0x00};
		}
		
		_logger.info("Sending command to get applet status: " + Util.bytesToHex(commandAPDU));
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);
		
		readInitialStateFromResponseAPDU(responseAPDU);
	}
	
	@Override
	public int getMaxNumberOfKeys() throws IOException {
		ensureInitialStateRead(false);
		return _maxNumberOfKeys;
	}
	
	@Override
	public int getCurrentNumberOfKeys() throws IOException {
		ensureInitialStateRead(false);
		return _currentNumberOfKeys;
	}

	private void readInitialStateFromResponseAPDU(byte[] responseAPDU) throws IOException {

        int bufferIndex = 0;

        _cardIdentifier = Util.bytesToHex(responseAPDU, bufferIndex, CARD_IDENTIFIER_LENGTH);

        _logger.info("Got card identifier of " + _cardIdentifier);
        bufferIndex += 8;

		_version[0] = responseAPDU[bufferIndex++];
		_version[1] = responseAPDU[bufferIndex++];
		_logger.info("Applet version: " + _version[0] + "" + _version[1]);
        _versionShort = Util.bytesToShort(_version, 0, 2);
		
		_pinState = PINState.NOT_SET;
		if ((responseAPDU[bufferIndex] & 0x80) != 0) {
			_pinState = PINState.SET; // the PIN is set
		}
		if ((responseAPDU[bufferIndex] & 0x40) != 0) {
			_pinState = PINState.BLANK; // the PIN is set to blank
		}
		_logger.info("PIN state: " + _pinState);

		_loggedIn = (responseAPDU[bufferIndex] & 0x20) != 0;
		_logger.info("Logged in: " + _loggedIn);

        _seedSet = (responseAPDU[bufferIndex] & 0x10) != 0;
        _logger.info("Seed set: " + _seedSet);

        bufferIndex++;

        // seed creation time (if not set will be zero's)
        _seedCreationTime = Util.bytesToLong(responseAPDU, bufferIndex, SEED_CREATION_TIME_SIZE);
        _logger.info("Got seed creation time: " + _seedCreationTime);
        bufferIndex += SEED_CREATION_TIME_SIZE;

		_passwordAttemptsLeft = responseAPDU[bufferIndex++] & 0xFF;
		_logger.info("Password attempts left: " + _passwordAttemptsLeft);
		
		_maxNumberOfKeys = responseAPDU[bufferIndex++] & 0xFF;
		_logger.info("Max number of keys: " + _maxNumberOfKeys);

        // Version 3 added a transaction number
		if (_versionShort >= 3) {
			_transactionNumber = Arrays.copyOfRange(responseAPDU, bufferIndex, bufferIndex + TRANSACTION_NUMBER_SIZE);
			_logger.info("Got transaction number: " +  Util.bytesToHex(_transactionNumber));
			bufferIndex += TRANSACTION_NUMBER_SIZE;
		}

		byte lengthOfPasswordMetaData = (byte)(responseAPDU[bufferIndex++] & 0xFF);
		_logger.info("Length of password meta data: " + lengthOfPasswordMetaData);
		
		if (lengthOfPasswordMetaData > 0) {
			// the rest is TLE encoded - read the data out
			ByteArrayInputStream stream = new ByteArrayInputStream(responseAPDU, bufferIndex, lengthOfPasswordMetaData);
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
						_logger.info("ensureInitialStateRead: read 0 length field");
						continue;
					}
					byte[] fieldData = new byte[fieldLength];
					if (stream.read(fieldData, 0, fieldLength) == -1) {
						_logger.error("ensureInitialStateRead: Field was missing bytes");
						return;
					}

					switch(fieldType) {
						case FIELD_PASSWORD_META_DATA_VERSION: {
							_passwordMetaDataVersion = fieldData[0] & 0xff; // expected one byte
							_logger.info("ensureInitialStateRead: read password meta data version " + _passwordMetaDataVersion);
							if (_passwordMetaDataVersion != 1) {
								throw new WrongVersionException();
							}
							break;
						}
						case FIELD_PASSWORD_META_DATA_PKCS5_ITERATION_COUNT: {
							_passwordPKCS5IterationCount = Util.bytesToInt(fieldData);
							_logger.info("ensureInitialStateRead: read iteration count of " + _passwordPKCS5IterationCount);
							break;
						}
						case FIELD_PASSWORD_META_DATA_PKCS5_PASSWORD_KEY_SALT: {
							_passwordPKCS5PasswordKeySalt = fieldData;
							_logger.info("ensureInitialStateRead: read password key salt of " + Util.bytesToHex(_passwordPKCS5PasswordKeySalt));
							break;
						}
						case FIELD_PASSWORD_META_DATA_PKCS5_ENCRYPTION_KEY_SALT: {
							_passwordPKCS5EncryptionKeySalt = fieldData;
							_logger.info("ensureInitialStateRead: read encryption key salt of " + Util.bytesToHex(_passwordPKCS5EncryptionKeySalt));
							break;
						}
						default: {
							_logger.info("ensureInitialStateRead: skipped unknown field");
							break;
						}
					}
				}
			} finally {
				try {
					stream.close();
				} catch (IOException e) {
					_logger.error("ensureInitialStateRead: error closing stream: " + e.toString());
				}
			}
		} else {
			_passwordMetaDataVersion = -1;
		}

		_currentState = SecureElementState.STATE_INFORMATION_READ;
	}
	
	private void ensureResponseEndsWith9000(byte[] responseAPDU) throws IOException {
		if (responseAPDU == null) {
			_logger.info("ensureResponseEndsWith9000: response was null");
			throw new IOException("Received null response from card.");			
		} else if (responseAPDU.length < 2) {
			_logger.info("ensureResponseEndsWith9000: response length less than 2");
			throw new IOException("Received response of less than 2 bytes");			
		}
		
		byte sw1 = responseAPDU[responseAPDU.length - 2];
		byte sw2 = responseAPDU[responseAPDU.length - 1];
		
		if (sw1 == (byte)0x90 && sw2 == (byte)0x00) {
			_logger.info("ensureResponseEndsWith9000: received good response from card");
			return;
		} else if (sw1 == (byte)0x69 && sw2 == (byte)0x82) {
			// SW_SECURITY_STATUS_NOT_SATISFIED
			_logger.info("ensureResponseEndsWith9000: wrong password");
			throw new WrongPasswordException();
		} else if (sw1 == (byte)0x6a && sw2 == (byte)0x84) {
			// SW_FILE_FULL
			throw new SmartCardFullException();
		} else if (sw1 == (byte)0x69 && sw2 == (byte)0x84) {
			// SW_INVALID_DATA
			throw new KeyAlreadyExistsException();
		} else if (sw1 == (byte)0x69 && sw2 == (byte)0x86) {
			// SW_COMMAND_NOT_ALLOWED
			throw new IOException("Command not allowed");
		} else if (sw1 == (byte)0x69 && sw2 == (byte)0x83) {
			_logger.info("ensureResponseEndsWith9000: card was wiped!");
			// force get the status again to refresh our view of the card
			// so that we know no PIN is set, for example
			ensureInitialStateRead(true);
			throw new CardWasWipedException();
		}
		
		throw new IOException("Received unknown response from card");
	}
	
	@Override
	public PINState getPINState() throws IOException {
		ensureInitialStateRead(false);
		return _pinState;
	}

	@Override
	public void setCardPassword(String oldPassword, String newPassword) throws IOException {
		ensureInitialStateRead(false);
		byte[] oldPasswordBytes = null;
		int oldPasswordBytesLength = 0;
		if (oldPassword != null && oldPassword.length() > 0) {
			PINState currentPINState = getPINState();
			if (currentPINState == PINState.NOT_SET || currentPINState == PINState.BLANK || _passwordMetaDataVersion == -1) {
				// we received a password, but there's no password set, or we have no password meta data
				// throw an error here
				_logger.error("setCardPassword: received old password, but no password set or no password meta data");
				throw new IOException("setCardPassword: received old password, but no password set or no password meta data");
			}

			// use PKCS5 derivation to derive the old password
			oldPasswordBytes = PKCS5Util.derivePKCS5Key(oldPassword, LENGTH_OF_PASSWORD_PKCS5_KEY_IN_BITS, _passwordPKCS5PasswordKeySalt, _passwordPKCS5IterationCount);
			oldPasswordBytesLength = oldPasswordBytes.length;
		}

		byte[] newPasswordBytes = null;
		int newPasswordBytesLength = 0;
		
		byte[] passwordMetaData = null;
		int passwordMetaDataLength = 0;
		if (newPassword != null && newPassword.length() > 0) {

			// generate the iteration counts and salts for the password key and encryption key
			int newPasswordPKCS5IterationCount = DEFAULT_ITERATION_COUNT;
			byte[] newPasswordPKCS5PasswordKeySalt = new byte[LENGTH_OF_PASSWORD_PKCS5_KEY_IN_BITS / 8];
			new Random().nextBytes(newPasswordPKCS5PasswordKeySalt);

			byte[] newPasswordPKCS5EncryptionKeySalt = new byte[LENGTH_OF_PASSWORD_PKCS5_KEY_IN_BITS / 8];
			new Random().nextBytes(newPasswordPKCS5EncryptionKeySalt);
			ByteArrayOutputStream passwordMetaDataOutputStream = new ByteArrayOutputStream();

			passwordMetaDataOutputStream.write(FIELD_PASSWORD_META_DATA_VERSION);
			passwordMetaDataOutputStream.write(0x01);
			passwordMetaDataOutputStream.write(0x01); // this code only writes version 1

			passwordMetaDataOutputStream.write(FIELD_PASSWORD_META_DATA_PKCS5_ITERATION_COUNT);
			passwordMetaDataOutputStream.write(0x04);
			passwordMetaDataOutputStream.write(Util.intToBytes(newPasswordPKCS5IterationCount));

			passwordMetaDataOutputStream.write(FIELD_PASSWORD_META_DATA_PKCS5_PASSWORD_KEY_SALT);			
			passwordMetaDataOutputStream.write(newPasswordPKCS5PasswordKeySalt.length);
			passwordMetaDataOutputStream.write(newPasswordPKCS5PasswordKeySalt);

			passwordMetaDataOutputStream.write(FIELD_PASSWORD_META_DATA_PKCS5_ENCRYPTION_KEY_SALT);			
			passwordMetaDataOutputStream.write(newPasswordPKCS5EncryptionKeySalt.length);
			passwordMetaDataOutputStream.write(newPasswordPKCS5EncryptionKeySalt);

			passwordMetaData = passwordMetaDataOutputStream.toByteArray();
			passwordMetaDataLength = passwordMetaData.length;
			
			// use PKCS5 to derive the new password
			newPasswordBytes = PKCS5Util.derivePKCS5Key(newPassword, LENGTH_OF_PASSWORD_PKCS5_KEY_IN_BITS, newPasswordPKCS5PasswordKeySalt, newPasswordPKCS5IterationCount);
			newPasswordBytesLength = newPasswordBytes.length;
		}

		// create an APDU with p1 set to length of old password, p2 set to length of new password
		byte[] commandAPDUInitializePassword = new byte[] {(byte)0x80, 0x02, (byte)(oldPasswordBytesLength), (byte)(newPasswordBytesLength), (byte)(oldPasswordBytesLength + newPasswordBytesLength + passwordMetaDataLength)};		
		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUInitializePassword.length + oldPasswordBytesLength + newPasswordBytesLength);

		commandAPDUByteArrayOutputStream.write(commandAPDUInitializePassword);
		// now write the old password and new password
		if (oldPasswordBytes != null) {
			commandAPDUByteArrayOutputStream.write(oldPasswordBytes);
		}
		if (newPasswordBytes != null) {
			commandAPDUByteArrayOutputStream.write(newPasswordBytes);
		}
		if (passwordMetaDataLength != 0) {
			commandAPDUByteArrayOutputStream.write(passwordMetaData);
		}

		byte[] finalCommandAPDU = commandAPDUByteArrayOutputStream.toByteArray();
		_logger.info("Sending command APDU to set password");
		// don't log the APDU itself as it's sensitive
		/*
		if (!Constants.PRODUCTION_BUILD) {
			_logger.info("APDU: " + Util.bytesToHex(finalCommandAPDU));
		}
		*/
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(finalCommandAPDU);
		_logger.info("Got response: " + Util.bytesToHex(responseAPDU));

		ensureResponseEndsWith9000(responseAPDU);

		// force a refresh the secure element state
		readInitialStateFromResponseAPDU(responseAPDU);
	}

    @Override
    public boolean isSeedSet() throws IOException {
        ensureInitialStateRead(false);
        return _seedSet;
    }

	public void injectTestSeed1() throws IOException {

		byte [] testVector1 = new byte [] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

		byte [] testVector2 = new byte [] {
				(byte)0xff, (byte)0xfc, (byte)0xf9, (byte)0xf6, (byte)0xf3, (byte)0xf0, (byte)0xed, (byte)0xea, (byte)0xe7,
				(byte)0xe4, (byte)0xe1, (byte)0xde, (byte)0xdb, (byte)0xd8, (byte)0xd5, (byte)0xd2, (byte)0xcf, (byte)0xcc,
				(byte)0xc9, (byte)0xc6, (byte)0xc3, (byte)0xc0, (byte)0xbd, (byte)0xba, (byte)0xb7, (byte)0xb4, (byte)0xb1,
				(byte)0xae, (byte)0xab, (byte)0xa8, (byte)0xa5, (byte)0xa2, (byte)0x9f, (byte)0x9c, (byte)0x99, (byte)0x96,
				(byte)0x93, (byte)0x90, (byte)0x8d, (byte)0x8a, (byte)0x87, (byte)0x84, (byte)0x81, (byte)0x7e, (byte)0x7b,
				(byte)0x78, (byte)0x75, (byte)0x72, (byte)0x6f, (byte)0x6c, (byte)0x69, (byte)0x66, (byte)0x63, (byte)0x60,
				(byte)0x5d, (byte)0x5a, (byte)0x57, (byte)0x54, (byte)0x51, (byte)0x4e, (byte)0x4b, (byte)0x48, (byte)0x45,
				(byte)0x42};

		_logger.info("injectTestSeed1: Injecting test seed 1");
		generateSeed(testVector1);
	}

	public void wipeCard() throws IOException {

		ensureInitialStateRead(false);

		byte[] commandAPDUHeader = new byte[]{(byte) 0x80, 0x09, 0x00, 0x00 };

		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length + 8 /*creation time is 8 bytes */);

		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);

		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

		_logger.info("wipeCard: Sending command APDU to wipe card: " + Util.bytesToHex(commandAPDU));
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("wipeCard: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);

	}

    @Override
    public void generateSeed() throws IOException {
        generateSeed(null);
    }

    @Override
    public void generateSeed(byte [] seed) throws IOException {

        ensureInitialStateRead(false);

		int lc = 8; // seed creation time
		if( seed != null) {
			lc += seed.length;
		}

		if( lc > 255) {
			throw new IOException("seed too long");
		}

        byte[] commandAPDUHeader = new byte[]{(byte) 0x80, 0x04, 0x00, 0x00, (byte)lc };

        ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length + 8 /*creation time is 8 bytes */);

        commandAPDUByteArrayOutputStream.write(commandAPDUHeader);

		// The seed creation time is 8 bytes and is meta data we provide so we can choose the units - we choose millis
        long seedCreationtime = System.currentTimeMillis();
        commandAPDUByteArrayOutputStream.write(Util.longToBytes(seedCreationtime));

		if (seed != null) {
			commandAPDUByteArrayOutputStream.write(seed);
		}

        byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

        _logger.info("generateSeed: Sending command APDU to generate seed: " + Util.bytesToHex(commandAPDU));
        byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
        _logger.info("generateSeed: Got response: " + Util.bytesToHex(responseAPDU));
        ensureResponseEndsWith9000(responseAPDU);

        _seedSet = true;
        _seedCreationTime = seedCreationtime;
    }

    @Override
	public void getAllData() throws IOException {
		boolean reGenerate = false;
//TODO: we only care about what is in slots 0-3. should we bother checking to see if the other
//slots are non-empty and delete them?
		for (int i = 0; i < 4; i++) {
			reGenerate = verifySlot(i, reGenerate);
		}
	}

    @Override
	public void setupCard() throws IOException {

        ensureInitialStateRead(true);

        if (!_seedSet) {
            generateSeed();
        }

		boolean reGenerate = false;
//TODO: we only care about what is in slots 0-3. should we bother checking to see if the other
//slots are non-empty and delete them?
		for (int i = 0; i < 4; i++) {
			reGenerate = verifySlot(i, reGenerate);
		}
	}

    @Override
	public Wallet getWallet() throws  IOException {

		// Now that all our slots are validated we can initialize the wallet

		// Wallet chain, external (m/0H) at slot 1
		SlotInfo slotInfo = getSlotInfo(1);
		if (slotInfo == null) {
			throw new IOException("unable to get slot info");
		}
		byte [] publicKeyEncoding = slotInfo.getCompressedECCPublicPoint();
		byte [] chainCode = slotInfo.getmChainCode();

//TODO: have SlotInfo just use the ImmutableList instead
		int [] i = slotInfo.getI();
		boolean [] hardenedI = slotInfo.getmIsHardenedI();

		ImmutableList.Builder<ChildNumber> builder=ImmutableList.builder();
		for ( int j = 0; j< i.length; j++ ) {
			builder.add(new ChildNumber(i[j], hardenedI[j]));
		}
		ImmutableList<ChildNumber> childNumberPath = builder.build();

		ECDomainParameters ecDomainParameters;
		X9ECParameters ecParams = SECNamedCurves.getByName("secp256k1");
		ecDomainParameters = new ECDomainParameters(ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());
		ECCurve ecCurve = ecDomainParameters.getCurve();
		ECPoint ecPoint = ecCurve.decodePoint(publicKeyEncoding);
		ECPoint newPoint = new ECPoint.Fp(ecCurve, ecPoint.getX(), ecPoint.getY(), false);
		LazyECPoint publicAsPoint = new LazyECPoint(newPoint);

		DeterministicKey watchKey = new DeterministicKey( childNumberPath, chainCode, publicAsPoint, null, null);
		return Wallet.fromWatchingKey(de.schildbach.wallet.Constants.NETWORK_PARAMETERS, watchKey);
	}


	/**
	 *
	 * @param slot
	 * @return true if the rest of the slots after this one need to be re-generated
	 * @throws IOException
	 */
	public boolean verifySlot(int slot, boolean reGenerate) throws IOException {

		ensureInitialStateRead(false);

		SlotInfo slotInfo = getSlotInfo(slot);
		boolean isEmpty = slotInfo == null;

		int[] i = null;
		if (slotInfo != null) {
			i = slotInfo.getI();
		}

		boolean tryAgain = false;

		switch (slot) {

			case 0:

				// Master Node (m) at slot 0

				for( int k = 0; k < 2; k++) {

					// If we have re-generated the slot, we need to check again to make sure everything looks good
					if (tryAgain) {
						slotInfo = getSlotInfo(slot);
						isEmpty = slotInfo == null;
						if (slotInfo != null) {
							i = slotInfo.getI();
						} else {
							i = null;
						}
					}

					if (isEmpty || (reGenerate && !tryAgain)) {

						if (isEmpty) {
							_logger.info(String.format("generating key for empty slot=%d", slot));
						} else {
							_logger.info(String.format("regenerating key for non-empty slot=%d", slot));
						}

						// If this is the second time through the loop we have already tried to regenerate
						// this slot, so now give up.
						if (k == 1) {
							throw new IOException("unable to generate wallet account in slot 1");
						}

						// Should have a master node (m) at slot 0
						generateMaster(0);
						reGenerate = true;
						tryAgain = true;

					} else {

						// Master Node m. I should be empty
						if (i.length != 0) {

							// Something is invalid
							_logger.error( String.format("detected issue in slot=%d, regenerating", slot) );

							// If this is the second time through the loop we have already tried to regenerate
							// this slot, so now give up.
							if (k == 1) {
								throw new IOException("unable to generate wallet account in slot 1");
							}

							// Re-generate everything after this slot because something is wrong, we should not have
							// a non-empty i for the master node.
							generateMaster(0);
							reGenerate = true;
							tryAgain = true;
						}
					}

					if(!tryAgain) {
						break;
					}
				}

				break;

			case 1:

				// Wallet account (m/0H) at slot 1

				for( int k = 0; k < 2; k++) {

					// If we have re-generated the slot, we need to check again to make sure everything looks good
					if (tryAgain) {
						slotInfo = getSlotInfo(slot);
						isEmpty = slotInfo == null;
						if (slotInfo != null) {
							i = slotInfo.getI();
						} else {
							i = null;
						}
					}

					// If the slot is empty OR
					// we were told to re generate the key (and it's not the second time through the loop)
					if (isEmpty || (reGenerate && !tryAgain)) {

						if (isEmpty) {
							_logger.info(String.format("generating key for empty slot=%d", slot));
						} else {
							_logger.info(String.format("regenerating key for non-empty slot=%d", slot));
						}

						// If this is the second time through the loop we have already tried to regenerate
						// this slot, so now give up.
						if (k == 1) {
							throw new IOException("unable to generate wallet account in slot 1");
						}

						// Wallet accounts (m/0H) at slot 1
						generateKey(0, 1, 0x80000000); // m/0H
						reGenerate = true;
						tryAgain = true;

					} else {

						// Check to make sure what is in the slot actually looks good
						// Length must be 1, i must be 0 and it must be hardened
						if (i.length != 1 || i[0] != 0 || !slotInfo.getIsHardenedI(0)) {

							// Something is invalid
							_logger.error( String.format("detected issue in slot=%d, regenerating", slot) );

							// If this is the second time through the loop we have already tried to regenerate
							// this slot, so now give up.
							if (k == 1) {
								throw new IOException("unable to generate wallet account in slot 1");
							}

							// Regenerate the wallet account (m/0H)
							generateKey(0, 1, 0x80000000); // m/0H
							reGenerate = true;
							tryAgain = true;
						}
					}

					if(!tryAgain) {
						break;
					}
				}

				// We have valid key in this slot, update the public key if needed
				if (slotInfo.getCompressedX() == 0x00) {
					// Need to update the public key for this node
					updatePublicKey(slot, slotInfo.getCompressedECCPublicPoint());
				}

				break;

			case 2:

				// Wallet chain, external (m/0H/0) at slot 2

				for( int k = 0; k < 2; k++) {

					// If we have re-generated the slot, we need to check again to make sure everything looks good
					if (tryAgain) {
						slotInfo = getSlotInfo(slot);
						isEmpty = slotInfo == null;
						if (slotInfo != null) {
							i = slotInfo.getI();
						} else {
							i = null;
						}
					}

					// If the slot is empty OR
					// we were told to re generate the key (and it's not the second time through the loop)
					if (isEmpty || (reGenerate && !tryAgain)) {

						if (isEmpty) {
							_logger.info(String.format("generating key for empty slot=%d", slot));
						} else {
							_logger.info(String.format("regenerating key for non-empty slot=%d", slot));
						}

						// If this is the second time through the loop we have already tried to regenerate
						// this slot, so now give up.
						if (k == 1) {
							throw new IOException("unable to generate wallet account in slot 1");
						}

						// Wallet chain (m/0H/0) at slot 2

						generateKey(1, 2, 0x00000000); // m/0H/0

						reGenerate = true;
						tryAgain = true;

					} else {

						// Check to make sure what is in the slot actually looks good
						// Length must be 2, i must be 0, 0 and first i must be hardened and secoond not hardened
						if (i.length != 2 || i[0] != 0 || i[1] != 0 || !slotInfo.getIsHardenedI(0) || slotInfo.getIsHardenedI(1)) {

							// Something is invalid
							_logger.error( String.format("detected issue in slot=%d, regenerating", slot) );

							// If this is the second time through the loop we have already tried to regenerate
							// this slot, so now give up.
							if (k == 1) {
								throw new IOException("unable to generate wallet account in slot 1");
							}

							// Regenerate the wallet account (m/0H/0)

							generateKey(1, 2, 0x00000000); // m/0H/0

							reGenerate = true;
							tryAgain = true;
						}
					}

					if(!tryAgain) {
						break;
					}
				}

				// We have valid key in this slot and since this key is not hardened we need to ensure
				// the card has the full public key for this slot
				if (slotInfo.getCompressedX() == 0x00) {
					// Need to update the public key for this node
					updatePublicKey(slot, slotInfo.getCompressedECCPublicPoint());
				}

				break;


			case 3:

				// Wallet chains, internal (m/0H/1) at slot 3

				for( int k = 0; k < 2; k++) {

					// If we have re-generated the slot, we need to check again to make sure everything looks good
					if (tryAgain) {
						slotInfo = getSlotInfo(slot);
						isEmpty = slotInfo == null;
						if (slotInfo != null) {
							i = slotInfo.getI();
						} else {
							i = null;
						}
					}

					// If the slot is empty OR
					// we were told to re generate the key (and it's not the second time through the loop)
					if (isEmpty || (reGenerate && !tryAgain)) {

						if (isEmpty) {
							_logger.info(String.format("generating key for empty slot=%d", slot));
						} else {
							_logger.info(String.format("regenerating key for non-empty slot=%d", slot));
						}

						// If this is the second time through the loop we have already tried to regenerate
						// this slot, so now give up.
						if (k == 1) {
							throw new IOException("unable to generate wallet account in slot 1");
						}

						// Wallet chain (m/0H/1) at slot 3

						generateKey(1, 3, 0x00000001); // m/0H/1

						reGenerate = true;
						tryAgain = true;

					} else {

						// Check to make sure what is in the slot actually looks good
						// Length must be 2, i must be 0, 1 and first i must be hardened and secoond not hardened
						if (i.length != 2 || i[0] != 0 || i[1] != 1 || !slotInfo.getIsHardenedI(0) || slotInfo.getIsHardenedI(1)) {

							// Something is invalid
							_logger.error( String.format("detected issue in slot=%d, regenerating", slot) );

							// If this is the second time through the loop we have already tried to regenerate
							// this slot, so now give up.
							if (k == 1) {
								throw new IOException("unable to generate wallet account in slot 1");
							}

							// Regenerate the wallet chain (m/0H/1)

							generateKey(1, 3, 0x00000001 ); // m/0H/1

							reGenerate = true;
							tryAgain = true;
						}
					}

					if(!tryAgain) {
						break;
					}
				}

				// We have valid key in this slot and since this key is not hardened we need to ensure
				// the card has the full public key for this slot
				if (slotInfo.getCompressedX() == 0x00) {
					// Need to update the public key for this node
					updatePublicKey(slot, slotInfo.getCompressedECCPublicPoint());
				}

				break;

		}

		return reGenerate;
	}


	private SlotInfo getSlotInfo(int slot) throws IOException {

		ensureInitialStateRead(false);

		byte[] commandAPDUHeader = new byte[]{(byte) 0x80, 0x06, 0x02 /*get the public key info*/, (byte) slot};

		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length);

		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);

		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

		_logger.info("getData: Sending command APDU to get data from slot= " + slot + ", APDU=" + Util.bytesToHex(commandAPDU));
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("getData: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);

		boolean isEmpty = responseAPDU.length == 2;
		if (isEmpty) {
			return null;
		} else {
			return parseSlotInfo(slot, responseAPDU);
		}
	}


	private class SlotInfo {

		int [] mI;
		boolean [] mIsHardenedI;
		byte[] mCompressedECCPublicPoint;
		byte [] mChainCode;

		SlotInfo( int [] i, boolean [] isHardenedI, byte [] compressedECCPublicPoint, byte [] chainCode) {
			mI = i;
			mIsHardenedI = isHardenedI;
			mCompressedECCPublicPoint = compressedECCPublicPoint;
			mChainCode = chainCode;
		}

		int [] getI() {
			return mI;
		}

		/**
		 * return true if the i at the given index is hardened or not
		 */
		boolean getIsHardenedI( int index ) {
			return mIsHardenedI[index];
		}

		boolean [] getmIsHardenedI() {
			return mIsHardenedI;
		}

		byte [] getCompressedECCPublicPoint() {
			return mCompressedECCPublicPoint;
		}

		byte [] getmChainCode() {
			return mChainCode;
		}

		byte getCompressedX() {
			return mCompressedECCPublicPoint[0];
		}
	}


	private SlotInfo parseSlotInfo( int slot, byte [] responseAPDU ) throws  IOException {

		if (responseAPDU.length < 68) { // 1 (length of I) + 33 (y) + 32 (chain code) + 2 (0x90, 0x00)
			throw new IOException("getData: not enough response data for slot=" + slot + " size=" + responseAPDU.length);
		}

		ByteArrayInputStream stream = new ByteArrayInputStream(responseAPDU);
		try {

			int lengthOfI = stream.read();

			int numIsToRead = lengthOfI / 4;
			if (numIsToRead > 8) {
				throw new IOException("parseSlotInfo: abnormal number of i's");
			}

			int [] iArray = new int[numIsToRead];
			boolean [] iHardenedArray = new boolean[numIsToRead];

			for (int k = 0; k < numIsToRead; k++) {
				byte[] temp = new byte[4];
				if (stream.read(temp, 0, 4) == -1) {
					String message = "parseSlotInfo: missing i";
					_logger.error(message);
					throw new IOException(message);
				} else {
					// Found and i, show the value
					if ((byte) (temp[0] & 0x80) != 0) {
						_logger.info("parseSlotInfo: found hardened i");

						// Clear the hardened bit
						temp[0] = (byte) (temp[0] & 0x7f);

						iHardenedArray[k] = true;
					} else {
						iHardenedArray[k] = false;
					}

					int i = Util.bytesToInt(temp);
					iArray[k] = i;
					_logger.info("getData: found i=" + i);
				}
			}

			// data left - 33 (y) + 32 (chain code) + 2 (0x90, 0x00)
			if (stream.available() != 67) {
				String message = "parseSlotInfo: not enough response data in input stream for slot= " + slot + " size=" + stream.available();
				_logger.error(message);
				throw new IOException(message);
			}

			byte[] compressedECCPublicPoint = new byte[33]; //(compressed y + 32 bytes of X)
			if (stream.read(compressedECCPublicPoint, 0, 33) == -1) {
				String message = "parseSlotInfo: missing compressedECCPublicPoint for slot=" + slot;
				_logger.error(message);
				throw new IOException(message);
			} else {
				_logger.info("parseSlotInfo: for slot= " + slot + " compressedECCPublicPoint=" + Util.bytesToHex(compressedECCPublicPoint));
			}
			byte compressedY = compressedECCPublicPoint[0];
			if (compressedY == 0x00) {
				_logger.info("parseSlotInfo: needs compressed, slot=" + slot);
			}

			byte[] chainCode = new byte[32];
			if (stream.read(chainCode, 0, 32) == -1) {
				String message = "getData: missing chainCode for slot=" + slot;
				_logger.error(message);
				throw new IOException(message);
			} else {
				_logger.info("parseSlotInfo: chainCode for slot= " + slot + " chainCode=" + Util.bytesToHex(chainCode));
			}

			return new SlotInfo( iArray, iHardenedArray, compressedECCPublicPoint, chainCode);

		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				String message = "parseSlotInfo: error closing stream: for slot= " + slot + " e=" + e.toString();
				_logger.error(message);
			}
		}
	}


/**
	* 1st byte - length of i
	*    i (based on length)
	*    33 bytes - compressed ecc public key
	*       1st byte (the compressed x coordinate) - 0 or non zero.
	*           If 0 needs the compressed x back from the phone followed by the rest of key
	*           If non zero it's the full publickey
			*       32 bytes - the y coordinate of ECC public key
	*    32 bytes - the chain code
	*
			*  0x69, 0x82 (SW_SECURITY_STATUS_NOT_SATISFIED) - If not logged in
*/
	public void generateMaster(int slot) throws IOException {

		ensureInitialStateRead(false);

		byte[] commandAPDUHeader = new byte[]{(byte) 0x80, 0x05, (byte)0xff /*generate master key*/, (byte)slot /*where to put the master key*/};

		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length);

		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);

		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

		_logger.info("getData: Sending command APDU to generate master key: " + Util.bytesToHex(commandAPDU));
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("getData: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);
	}


	public void updatePublicKey(int slot, byte[] publicKeyEncoding) throws IOException {

		// The point we need is either with header=0x02 or 0x03
		// First try 0x02 and if that doesn't work try 0x03

		_logger.info("PUT KEY - attempting 0x02");
		if( !tryUpdatePublicKey(slot, publicKeyEncoding, (byte)0x02) ) {
			_logger.info("PUT KEY - attempting 0x02 (FAILED)");
			_logger.info("PUT KEY - attempting 0x03");
			if( !tryUpdatePublicKey(slot, publicKeyEncoding, (byte)0x03) ) {
				_logger.info("PUT KEY - attempting 0x03 (FAILED)");
				throw new IOException("unable to update public key");
			} else {
				_logger.info("PUT KEY - attempting 0x03 (SUCCESS)");
			}
		} else {
			_logger.info("PUT KEY - attempting 0x02 (SUCCESS)");
		}
	}

	private boolean tryUpdatePublicKey(int slot, byte[] publicKeyEncoding, byte header) throws IOException {

		publicKeyEncoding[0] = header;

		byte[] publicKey = ECUtil.getPublicKeyBytesFromEncoding(publicKeyEncoding, false);

		if( publicKey.length != 65) {
			throw new IOException("wrong public key length");
		}

		byte[] commandAPDUHeader = new byte[]{(byte) 0x80, 0x07, (byte)slot, 0x00 /*unused?*/, (byte)32 /*Lc*/};
		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length);

		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);
		commandAPDUByteArrayOutputStream.write(publicKey, 33, 32);

		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

		_logger.info("updatePublicKey: Sending command APDU to updatePublicKey: " + Util.bytesToHex(commandAPDU));
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("updatePublicKey: Got response: " + Util.bytesToHex(responseAPDU));

		ensureResponseEndsWith9000(responseAPDU);

		if (responseAPDU.length != 3) {
			throw new IOException("invalid response length from put public key");
		}

		if( responseAPDU[0] == 0x01) {
			return true;
		} else {
			return false;
		}
	}

	public void generateKey(int sourceSlot, int destinationSlot, int i) throws IOException {

		ensureInitialStateRead(false);

		byte[] commandAPDUHeader = new byte[]{(byte) 0x80, 0x05, (byte)sourceSlot, (byte)destinationSlot, (byte)4 /*Lcsize of i*/};

		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length );
		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);

		byte [] iBytes = Util.intToBytes(i);
		commandAPDUByteArrayOutputStream.write(iBytes);

		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

		boolean isHardened = (i & 0x80000000) != 0;
		if (isHardened) {
			_logger.info("generateKey: Sending command APDU to generate hardened key: " + Util.bytesToHex(commandAPDU));
		} else {
			_logger.info("generateKey: Sending command APDU to generate NON-hardened key: " + Util.bytesToHex(commandAPDU));
		}
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("generateKey: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);
	}

	public void deleteKey(int slot) throws IOException {

		ensureInitialStateRead(false);

		byte[] commandAPDU = new byte[]{(byte) 0x80, 0x08, (byte)slot, 0x00 /*unused*/ };

		_logger.info("deleteKey: Sending command APDU to delete key: " + Util.bytesToHex(commandAPDU));
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("deleteKey: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);
	}

	@Override
	public void close() {
		_smartCardReader.close();
	}


	@Override
	public boolean checkConnection() {
		// TODO Auto-generated method stub
		return _smartCardReader.checkConnection();
	}

	@Override
	public byte[] doSimpleSign(byte parentSlot, byte[] beginningOfToAdd, byte[] bytesToSign, byte [] antiMalwareKey) throws IOException {

		ensureInitialStateRead(false);

        if ( (beginningOfToAdd == null) || (beginningOfToAdd.length != PRE_COMPUTED_HASH_SIZE) ) {
            throw new IllegalArgumentException("invalid beginningOfToAdd");
        }

        if ( (antiMalwareKey == null) || (antiMalwareKey.length != ANTI_MALWARE_KEY_SIZE) ) {
            throw new IllegalArgumentException("invalid antiMalwareKey");
        }

        byte lengthNeededForPayload = (byte)(PRE_COMPUTED_HASH_SIZE + ANTI_MALWARE_KEY_SIZE + bytesToSign.length);
		byte[] commandAPDUHeader = new byte[] {(byte)0x80, 0x0C, parentSlot, 0x00, lengthNeededForPayload};

		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length + lengthNeededForPayload);

		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);
		commandAPDUByteArrayOutputStream.write(antiMalwareKey);
        commandAPDUByteArrayOutputStream.write(beginningOfToAdd);
		commandAPDUByteArrayOutputStream.write(bytesToSign);

		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

		_logger.info("doSimpleSign: Sending command APDU to start signing");
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("doSimpleSign: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);

		// strip off the status words and return the result
		return Arrays.copyOfRange(responseAPDU, 0, responseAPDU.length - 2);
	}

	@Override
	public void beginTransactionSigningOperation(String password, byte[] destinationAddress, long amount) throws IOException {
		ensureInitialStateRead(false);
		
		byte[] passwordBytes = password.getBytes();
		int lengthOfPasswordBytes = passwordBytes.length;
		
		int lengthOfDestinationAddress = destinationAddress.length;
		
		byte[] amountBytes = Util.longToBytes(amount);
		int lengthOFAmountBytes = amountBytes.length;

		
		byte lengthNeededForPayload = (byte)(3 + lengthOfPasswordBytes + lengthOfDestinationAddress + lengthOFAmountBytes);
		byte[] commandAPDUHeader = new byte[] {(byte)0x80, 0x08, 0x00, 0x00, lengthNeededForPayload};
		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length + lengthNeededForPayload);
		
		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);
		commandAPDUByteArrayOutputStream.write(lengthOfPasswordBytes);
		commandAPDUByteArrayOutputStream.write(passwordBytes);
		commandAPDUByteArrayOutputStream.write(lengthOfDestinationAddress);
		commandAPDUByteArrayOutputStream.write(destinationAddress);
		commandAPDUByteArrayOutputStream.write(lengthOFAmountBytes);
		commandAPDUByteArrayOutputStream.write(amountBytes);
		
		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

		_logger.info("beginTransactionSigningOperation: Sending command APDU to start signing");
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("beginTransactionSigningOperation: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);
	}

	@Override
	public boolean isAuthenticated() throws IOException {
		ensureInitialStateRead(false);
		return _loggedIn;
	}

	@Override
	public byte[] login(String password, byte[] passwordBytes) throws IOException {
		_logger.info("login: called");
		ensureInitialStateRead(false);
		if (isAuthenticated()) {
			// already authenticated, nothing to do
			_logger.info("login: already authenticated");
			return null;
		}

		// use PKCS5 derivation to derive the password
		if (passwordBytes == null) {
			passwordBytes = PKCS5Util.derivePKCS5Key(password, LENGTH_OF_PASSWORD_PKCS5_KEY_IN_BITS, _passwordPKCS5PasswordKeySalt, _passwordPKCS5IterationCount);
		}
		int lengthOfPasswordBytes = passwordBytes.length;
				
		byte[] commandAPDUHeader = new byte[] {(byte)0x80, 0x03, 0x00, 0x00, (byte)lengthOfPasswordBytes};
		
		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length + lengthOfPasswordBytes);

		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);
		commandAPDUByteArrayOutputStream.write(passwordBytes);

		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

		_logger.info("login: Sending command APDU to login");
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("login: Got response: " + Util.bytesToHex(responseAPDU));
		
		
		byte sw1 = responseAPDU[responseAPDU.length - 2];
		byte sw2 = responseAPDU[responseAPDU.length - 1];
		
		if (sw1 == (byte)0x90 && sw2 == (byte)0x00) {
			// if we logged in successfully, the response contains the initial state
			// force a status refresh from the card to update the PIN attempts left count
			readInitialStateFromResponseAPDU(responseAPDU);
		} else {
			// otherwise we have to send a command to force read it
			ensureInitialStateRead(true);
		}

		ensureResponseEndsWith9000(responseAPDU);

		return passwordBytes;
	}

	@Override
	public ECKeyEntry createOrInjectKey(byte[] associatedDataBytes, String friendlyName, byte[] privateKey,
			byte[] publicKey, long creationTimeMillis) throws IOException {
		_logger.info("createOrInjectKey: called");
		ensureInitialStateRead(false);
		if (!isAuthenticated()) {
			// already authenticated, nothing to do
			_logger.error("createOrInjectKey: Not authenticated");
			throw new IOException("createOrInjectKey: Not authenticated");
		}

		int lengthOfPrivateKey = 0;
		int lengthOfPublicKey = 0;
		boolean publicKeyWasCompressed = false;
		if (privateKey != null && publicKey != null) {
			byte[] uncompressedPublicKey = ECUtil.getPublicKeyBytesFromEncoding(publicKey, false); // make sure we have an uncompressed encoding of the public key
			if (uncompressedPublicKey != publicKey) {
				// the original key was compressed
				publicKeyWasCompressed = true;
				publicKey = uncompressedPublicKey;
			}
			lengthOfPrivateKey = privateKey.length;
			lengthOfPublicKey = publicKey.length;
			if (lengthOfPrivateKey != LENGTH_OF_PRIVATE_KEY || lengthOfPublicKey != LENGTH_OF_PUBLIC_KEY) {
				throw new IllegalArgumentException("Key length was wrong.");
			}
		}

		if (associatedDataBytes == null) {
			// the caller did not supply associated data, generate it for caller
			byte[] friendlyNameBytes = friendlyName.getBytes();
			int lengthOfFriendlyNameBytes = friendlyNameBytes.length;
			
			ByteArrayOutputStream associatedDataByteArrayOutputStream = new ByteArrayOutputStream(64);
			associatedDataByteArrayOutputStream.write(ECKeyEntry.ASSOCIATED_DATA_TYPE_VERSION);
			associatedDataByteArrayOutputStream.write(0x01);
			associatedDataByteArrayOutputStream.write(0x01);
			
			associatedDataByteArrayOutputStream.write(ECKeyEntry.ASSOCIATED_DATA_TYPE_FRIENDLY_NAME);
			associatedDataByteArrayOutputStream.write(lengthOfFriendlyNameBytes);
			associatedDataByteArrayOutputStream.write(friendlyNameBytes);
			
			associatedDataByteArrayOutputStream.write(ECKeyEntry.ASSOCIATED_DATA_TYPE_GENERATION_TIME);
			associatedDataByteArrayOutputStream.write(0x08);
			associatedDataByteArrayOutputStream.write(Util.longToBytes(creationTimeMillis));

			associatedDataByteArrayOutputStream.write(ECKeyEntry.ASSOCIATED_DATA_TYPE_MISC_BIT_FIELD);
			associatedDataByteArrayOutputStream.write(0x01);
			associatedDataByteArrayOutputStream.write(publicKeyWasCompressed ? 0x80 : 0x00); 
			
			// we need a total of 64 bytes of associated data, pad the stream
			int lengthSoFar = associatedDataByteArrayOutputStream.size();
			int bytesToWrite = LENGTH_OF_ASSOCIATED_DATA - lengthSoFar;
			for (int i = 0; i < bytesToWrite; i++) {
				associatedDataByteArrayOutputStream.write(0);
			}
			
			associatedDataBytes = associatedDataByteArrayOutputStream.toByteArray();
		}
		
		int lengthOfAssociatedDataBytes = associatedDataBytes.length;
		
		int totalLengthOfCommandAPDU = lengthOfAssociatedDataBytes + lengthOfPrivateKey + lengthOfPublicKey; 
		
		byte[] commandAPDUHeader = new byte[] {(byte)0x80, 0x04, 0x00, 0x00, (byte)(totalLengthOfCommandAPDU)};
		
		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length + totalLengthOfCommandAPDU);
		
		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);
		commandAPDUByteArrayOutputStream.write(associatedDataBytes);
		if (lengthOfPrivateKey != 0 && lengthOfPublicKey != 0) {
			// we're injecting a private/public key pair
			commandAPDUByteArrayOutputStream.write(privateKey);
			commandAPDUByteArrayOutputStream.write(publicKey);
		}
		
		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();
		
		_logger.info("createOrInjectKey: Sending command APDU to inject key: " + Util.bytesToHex(commandAPDU));
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("createOrInjectKey: Got response: " + Util.bytesToHex(responseAPDU));
		
		ensureResponseEndsWith9000(responseAPDU);

		boolean isLocked = extractIsLocked(responseAPDU);
		
		// copy the public key bytes out
		byte[] publicKeyBytesFromSecureElement = extractPublicKey(responseAPDU);
		
		// copy the associated data bytes out
		byte[] associatedDataBytesFromSecureElement = extractAssociatedData(responseAPDU);

		return new ECKeyEntry(isLocked, publicKeyBytesFromSecureElement, associatedDataBytesFromSecureElement, null);
	}
	
	private static boolean extractIsLocked(byte[] responseAPDU) {
		return responseAPDU[0] == 1;
	}
	
	private static byte[] extractPublicKey(byte[] responseAPDU) {
		byte[] publicKeyBytesFromSecureElement = new byte[LENGTH_OF_PUBLIC_KEY];
		System.arraycopy(responseAPDU, 1, publicKeyBytesFromSecureElement, 0, LENGTH_OF_PUBLIC_KEY);
		return publicKeyBytesFromSecureElement;
	}
	
	private static byte[] extractAssociatedData(byte[] responseAPDU) {
		// copy the associated data bytes out
		byte[] associatedDataBytesFromSecureElement = new byte[LENGTH_OF_ASSOCIATED_DATA];
		System.arraycopy(responseAPDU, 1 + LENGTH_OF_PUBLIC_KEY, associatedDataBytesFromSecureElement, 0, LENGTH_OF_ASSOCIATED_DATA);
		return associatedDataBytesFromSecureElement;
	}
	
	private static byte[] extractPrivateKey(byte[] responseAPDU) {
		byte[] privateKeyBytesFromSecureElement = new byte[LENGTH_OF_PRIVATE_KEY];
		System.arraycopy(responseAPDU, 1 + LENGTH_OF_PUBLIC_KEY + LENGTH_OF_ASSOCIATED_DATA, privateKeyBytesFromSecureElement, 0, LENGTH_OF_PRIVATE_KEY);
		return privateKeyBytesFromSecureElement;
	}

	@Override
	public int getNumberPasswordAttemptsLeft() throws IOException {
		_logger.info("getNumberPasswordAttemptsLeft: called");
		ensureInitialStateRead(false);
		return _passwordAttemptsLeft;
	}

	@Override
	public void deleteKey(byte[] publicKey) throws IOException {
		_logger.info("deleteKey: called");
		// get the uncompressed form of the key, that's all the applet knows how to deal with
		byte[] publicKeyUncompressed = ECUtil.getPublicKeyBytesFromEncoding(publicKey, false);
		int lengthOfPublicKeyUncompressed = publicKeyUncompressed.length;
		byte[] commandAPDUHeader = new byte[] {(byte)0x80, 0x06, 0x00, 0x00, (byte)lengthOfPublicKeyUncompressed};
		
		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length + lengthOfPublicKeyUncompressed);
		
		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);
		commandAPDUByteArrayOutputStream.write(publicKeyUncompressed);
		
		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();
		
		_logger.info("deleteKey: Sending command APDU");
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("deleteKey: Got response: " + Util.bytesToHex(responseAPDU));
		
		ensureResponseEndsWith9000(responseAPDU);
	}

	@Override
	public void changeLabel(byte[] publicKey, String label) throws IOException {
		_logger.info("changeLabel: called");
		ensureInitialStateRead(false);
		
		publicKey = ECUtil.getPublicKeyBytesFromEncoding(publicKey, false); // get the uncompressed form of the public key
		
		int lengthOfPublicKey = publicKey.length;
		
		if (lengthOfPublicKey != LENGTH_OF_PUBLIC_KEY) {
			throw new IllegalArgumentException("Bad public key length");
		}
		
		// first get the associated data for this key
		byte[] commandAPDUHeader = new byte[] {(byte)0x80, 0x0D, 0x00, 0x00, (byte)lengthOfPublicKey};
		
		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length + lengthOfPublicKey);
		
		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);
		commandAPDUByteArrayOutputStream.write(publicKey);
		
		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();
		
		_logger.info("login: Sending command APDU to get associated key data");
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("login: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);		

		// extract the associated data
		byte[] associatedDataBytesFromSecureElement = extractAssociatedData(responseAPDU);
		

		ByteArrayOutputStream updatedAssociatedDataByteArrayOutputStream = new ByteArrayOutputStream(LENGTH_OF_ASSOCIATED_DATA);
		// we want to go through the associated data bytes, leaving all fields the same except for the label field
		ByteArrayInputStream stream = new ByteArrayInputStream(associatedDataBytesFromSecureElement);
		try {
			while (stream.available() > 0) {
				int fieldType = stream.read();
				if (fieldType == -1 || fieldType == 0) {
					// reached end of stream
					break;
				}
				int fieldLength = stream.read();
				if (fieldLength == -1) {
					// reached end of stream
					break;
				}

				// write all fields back to our output buffer except the friendly name field
				if (fieldType != ECKeyEntry.ASSOCIATED_DATA_TYPE_FRIENDLY_NAME) {
					updatedAssociatedDataByteArrayOutputStream.write(fieldType);
					updatedAssociatedDataByteArrayOutputStream.write(fieldLength);
	
					if (fieldLength == 0) {
						// 0-length field?
						_logger.info("changeLabel: read 0 length field");
					} else {
						byte[] fieldData = new byte[fieldLength];
						if (stream.read(fieldData, 0, fieldLength) == -1) {
							_logger.error("changeLabel: Field was missing bytes");
						}
						updatedAssociatedDataByteArrayOutputStream.write(fieldData);
					}
				} else {
					// just skip the friendly name field
					byte[] fieldData = new byte[fieldLength];
					if (stream.read(fieldData, 0, fieldLength) == -1) {
						_logger.error("changeLabel: friendly name was missing bytes");
					}
				}
			}
			// now write the friendly name
			updatedAssociatedDataByteArrayOutputStream.write(ECKeyEntry.ASSOCIATED_DATA_TYPE_FRIENDLY_NAME);
			if (label == null) {
				label = "";
			}
			byte[] labelBytes = label.getBytes();
			updatedAssociatedDataByteArrayOutputStream.write(labelBytes.length);
			updatedAssociatedDataByteArrayOutputStream.write(labelBytes);
			
			// we need a total of 64 bytes of associated data, pad the stream
			int lengthSoFar = updatedAssociatedDataByteArrayOutputStream.size();
			int bytesToWrite = LENGTH_OF_ASSOCIATED_DATA - lengthSoFar;
			for (int i = 0; i < bytesToWrite; i++) {
				updatedAssociatedDataByteArrayOutputStream.write(0);
			}
			
			byte[] updatedAssociatedDataBytes = updatedAssociatedDataByteArrayOutputStream.toByteArray();
			
			int overallLength = LENGTH_OF_PUBLIC_KEY + LENGTH_OF_ASSOCIATED_DATA;
			byte[] updateKeyAPDUHeader = new byte[] {(byte)0x80, 0x07, 0x00, 0x00, (byte)overallLength};
			ByteArrayOutputStream updateKeyAPDUStream = new ByteArrayOutputStream(commandAPDUHeader.length + overallLength);
			
			updateKeyAPDUStream.write(updateKeyAPDUHeader);
			updateKeyAPDUStream.write(publicKey);
			updateKeyAPDUStream.write(updatedAssociatedDataBytes);
			
			byte[] updateKeyAPDU = updateKeyAPDUStream.toByteArray();
			
			_logger.info("changeLabel: Sending command APDU to update key: " + Util.bytesToHex(updateKeyAPDU));
			byte[] updateKeyResponseAPDU = _smartCardReader.exchangeAPDU(updateKeyAPDU);
			_logger.info("changeLabel: Got response: " + Util.bytesToHex(updateKeyResponseAPDU));
			ensureResponseEndsWith9000(updateKeyResponseAPDU);			
		} finally {
			try {
				stream.close();
			} catch (IOException e) {
				_logger.error("changeLabel: error closing stream: " + e.toString());
			}
		}
	}

    @Override
    public String getCardIdentifier() throws IOException {
        ensureInitialStateRead(false);
        return _cardIdentifier;
    }

    public byte[] enableCachedSigning() throws IOException {
		_logger.info("enableCachedSigning: called");
		ensureInitialStateRead(false);
				
		// No arguments needed for the command APDU
		byte[] commandAPDU = new byte[] {(byte)0x80, 0x08, 0x00, 0x00, 0x00};
		
		_logger.info("enableCachedSigning: Sending command APDU to enable cached signing");
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("enableCachedSigning: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);	
		
		// the response will be the cached signature identifier which we can later use to retrieve a cached signature
		byte[] cachedSigningIdentifier = new byte[responseAPDU.length - 2];
		System.arraycopy(responseAPDU, 0, cachedSigningIdentifier, 0, cachedSigningIdentifier.length);
		
		_logger.info("enableCachedSigning: cached signing identifer is: " + Util.bytesToHex(cachedSigningIdentifier));
		
		return cachedSigningIdentifier;
    }
    
    public byte[] getCachedSigningDataForIdentifier(String password, byte[] cacheIdentifier) throws IOException {
    	_logger.info("getCachedSigningDataForIdentifier: called");
    	ensureInitialStateRead(false);

		byte[] passwordBytes = null;
		int lengthOfPasswordBytes = 0;
		if (password != null && password.length() > 0) {
			passwordBytes = password.getBytes();
			lengthOfPasswordBytes = passwordBytes.length;
		}

		byte[] commandAPDUHeader = new byte[] {(byte)0x80, 0x09, 0x00, 0x00, (byte)lengthOfPasswordBytes};
		ByteArrayOutputStream commandAPDUByteArrayOutputStream = new ByteArrayOutputStream(commandAPDUHeader.length + lengthOfPasswordBytes);
		commandAPDUByteArrayOutputStream.write(commandAPDUHeader);
		if (passwordBytes != null) {
			commandAPDUByteArrayOutputStream.write(passwordBytes);
		}
		byte[] commandAPDU = commandAPDUByteArrayOutputStream.toByteArray();

		_logger.info("getCachedSigningDataForIdentifier: Sending command APDU to get cached signing identifier");
		byte[] responseAPDU = _smartCardReader.exchangeAPDU(commandAPDU);
		_logger.info("getCachedSigningDataForIdentifier: Got response: " + Util.bytesToHex(responseAPDU));
		ensureResponseEndsWith9000(responseAPDU);
		
	    int CACHE_IDENTIFIER_LENGTH = 4;
		if (responseAPDU.length < CACHE_IDENTIFIER_LENGTH + 1 + 2) {
			// no data came back - no 4 byte identifier + at least one byte signed data + SW1 + SW2
			_logger.info("getCachedSigningDataForIdentifier: no cached signature data");
			return null;
		}
		
		// the first 4 bytes are the cache identifier, the remaining bytes are the signature data
		for (int i = 0; i < CACHE_IDENTIFIER_LENGTH; i++) {
			if (cacheIdentifier[i] != responseAPDU[i]) {
				_logger.info("getCachedSigningDataForIdentifier: cache identifiers not equal, returning nothing");
				return null;
			}
		}
		
		// return the signature data
		byte[] signatureData = new byte[responseAPDU.length - CACHE_IDENTIFIER_LENGTH - 2]; // enough space subtract the cache identifier and the SW1/SW2 bytes
		System.arraycopy(responseAPDU, CACHE_IDENTIFIER_LENGTH, signatureData, 0, signatureData.length);
		_logger.info("getCachedSigningDataForIdentifier: returning signature data of " + Util.bytesToHex(signatureData));
		return signatureData;
    }
}
