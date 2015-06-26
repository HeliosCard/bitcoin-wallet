package com.helioscard.wallet.bitcoin.secureelement;

import org.spongycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.spongycastle.crypto.PBEParametersGenerator;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.digests.SHA256Digest;

public class PKCS5Util {
	public static byte[] derivePKCS5Key(String password, int keySizeInBits, byte[] salt, int iterations) {
		PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
		generator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password.toCharArray()), salt, iterations);
		KeyParameter key = (KeyParameter)generator.generateDerivedMacParameters(keySizeInBits);
		return key.getKey();
	}
}
