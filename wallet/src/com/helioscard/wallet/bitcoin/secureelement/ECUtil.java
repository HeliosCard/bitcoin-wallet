package com.helioscard.wallet.bitcoin.secureelement;

import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECPoint;

public class ECUtil {
	
	private static ECDomainParameters  _ecParams;
	static {
		X9ECParameters params = SECNamedCurves.getByName("secp256k1");
		_ecParams = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
	}
	
	public static byte[] getPublicKeyBytesFromEncoding(byte[] publicKeyEncoding, boolean compressed) {
		// read the point into a SpongCastle structure
		ECCurve ecCurve = _ecParams.getCurve();
		ECPoint originalPoint = ecCurve.decodePoint(publicKeyEncoding);
		if (originalPoint.isCompressed() == compressed) {
			// the caller wants back a point encoded in the way it's already encoded
			return publicKeyEncoding;
		}
		
		// now re-create the point as a compressed or uncompressed point via SpongyCastle
        ECPoint newPoint = new ECPoint.Fp(ecCurve, originalPoint.getX(), originalPoint.getY(), compressed);
        return newPoint.getEncoded();
	}
}
