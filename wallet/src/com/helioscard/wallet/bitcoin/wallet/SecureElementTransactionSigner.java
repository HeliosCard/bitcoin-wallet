package com.helioscard.wallet.bitcoin.wallet;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;
import static org.bitcoinj.core.Utils.uint32ToByteStreamLE;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.ScriptException;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.UnsafeByteArrayOutputStream;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.Wallet;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDUtils;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptOpCodes;
import org.bitcoinj.wallet.DecryptingKeyBag;
import org.bitcoinj.wallet.KeyBag;
import org.bitcoinj.wallet.RedeemData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import android.content.Context;
import android.nfc.TagLostException;
import android.os.AsyncTask;

import com.google.common.collect.ImmutableList;
import com.helioscard.wallet.bitcoin.Constants;
import com.helioscard.wallet.bitcoin.secureelement.SecureElementApplet;
import com.helioscard.wallet.bitcoin.util.Util;

public class SecureElementTransactionSigner extends AsyncTask<SecureElementApplet, Integer, Integer> {

	private static Logger _logger = LoggerFactory.getLogger(SecureElementTransactionSigner.class);

	public static final int FINISHED = 0;
	public static final int TAG_LOST = 1;
	public static final int ERROR = 2;
	public static final int CANCELED = 3;
    public static final int NO_ANTI_MALWARE_KEY = 4;
	
	private volatile Listener _listener;
	private volatile Transaction _transaction;
	private volatile Address _returnAddress;
	private volatile Coin _finalAmount;
	private volatile Wallet _wallet;
	private volatile TransactionSignature[] _signatures;
    private volatile ECKey[] _signingKeys;

	private volatile byte[][] _dataToSign;
    private volatile byte[][] _beginningOfToAdds;

    private volatile byte[] _parentKeySlots;

	private volatile int _currentInputIndex;
	private volatile byte[] _hashedPasswordBytes;
    private volatile Wallet.SendRequest _sendRequest;
    private volatile byte [] _antiMalwareKey;

	public interface Listener {
		void secureElementTransactionSignerProgress(int progress);
		void secureElementTransactionListenerSignerFinished(int result);
	}
	
	public SecureElementTransactionSigner(byte [] antiMalwareKey, Listener listener, Wallet.SendRequest sendRequest /*, Address returnAddress*/, Coin finalAmount, Wallet wallet) {
        _sendRequest = sendRequest;
		_listener = listener;
		_transaction = sendRequest.tx;
		_finalAmount = finalAmount;
		_wallet = wallet;
        _antiMalwareKey = antiMalwareKey;


        int numInputs = _transaction.getInputs().size();
        _signatures = new TransactionSignature[numInputs];
        _dataToSign = new byte[numInputs][];
        _beginningOfToAdds = new byte[numInputs][];
        _parentKeySlots = new byte[numInputs];
        _signingKeys = new ECKey[numInputs];
	}
	
	public SecureElementTransactionSigner(SecureElementTransactionSigner secureElementTransactionSigner) {
        _sendRequest = secureElementTransactionSigner._sendRequest;
		_listener = secureElementTransactionSigner._listener;
		_transaction = secureElementTransactionSigner._transaction;
//		_returnAddress = secureElementTransactionSigner._returnAddress;
		_finalAmount = secureElementTransactionSigner._finalAmount;
		_wallet = secureElementTransactionSigner._wallet;
		_signatures = secureElementTransactionSigner._signatures;
		_dataToSign = secureElementTransactionSigner._dataToSign;
		_currentInputIndex = secureElementTransactionSigner._currentInputIndex;
		_hashedPasswordBytes = secureElementTransactionSigner._hashedPasswordBytes;
        _signingKeys = secureElementTransactionSigner._signingKeys;
        _antiMalwareKey = secureElementTransactionSigner._antiMalwareKey;

        _beginningOfToAdds = secureElementTransactionSigner._beginningOfToAdds;

        _parentKeySlots = secureElementTransactionSigner._parentKeySlots;
	}

	public Transaction getTransaction() {
		return _transaction;
	}
	
	public int getNumInputs() {
		return _transaction.getInputs().size();
	}
	
//	public Address getReturnAddress() {
//		return _returnAddress;
//	}
	
	public Coin getFinalAmount() {
		return _finalAmount;
	}
	
	public void setHashedPasswordBytes(byte[] hashedPasswordBytes) {
		_hashedPasswordBytes = hashedPasswordBytes;
	}

	/*
     * This function is a combination of the core bitcoinj functions Transaction.signInputs,
     * Transaction.calculateSignature and Transaction.hashForSignature.  We alter the functions to assume that we only operate
     * in SigHash.ALL mode (e.g. we are signing the transaction in a standard way, mandating both the inputs and the outputs are covered
     * by our signature), and anyonecanpay mode is off.
     */
	@Override
	protected Integer doInBackground(SecureElementApplet... params) {
        _logger.info("signTransaction: attempting to sign transaction");
        int resultCode = SecureElementTransactionSigner.FINISHED;
        try {

            if (_antiMalwareKey == null) {
                return SecureElementTransactionSigner.NO_ANTI_MALWARE_KEY;
            }

            SecureElementApplet secureElementApplet = params[0];

            if (!secureElementApplet.isAuthenticated()) {
                _logger.info("signTransaction: encountered unauthenticated secure element, trying to login");
                secureElementApplet.login(null, _hashedPasswordBytes);
            }

            // Adapted from Wallet.java

            List<TransactionInput> inputs = _transaction.getInputs();
            List<TransactionOutput> outputs = _transaction.getOutputs();
            checkState(inputs.size() > 0);
            checkState(outputs.size() > 0);

            if (Constants.TRANSACTION_LOGGING) {
                _logger.error("Transaction Info");
                _logger.error(String.format("Total Amount: %d", _finalAmount.getValue()));

                int nOutputs = outputs.size();
                _logger.error(String.format("Number of outputs: %d", nOutputs));
                for (TransactionOutput txOut : outputs) {
                    _logger.error(String.format("  Out: %s", txOut.toString()));
                    _logger.error(String.format("  Out value: %d", txOut.getValue().getValue()));
                }

                int nInputs = inputs.size();
                _logger.error(String.format("Number of inputs: %d", nInputs));
                for (TransactionInput txIn : inputs) {
                    _logger.error(String.format("  In: %s", txIn.toString()));
                    _logger.error(String.format("  In value: %d", txIn.getValue().getValue()));
                }

                String preRemovalSerializedTransaction = Util.bytesToHex(getSerializedTransaction());
                _logger.error( String.format("Serialized transaction before removing inputs: transaction=%s", preRemovalSerializedTransaction));
            }


            // The transaction is signed with the input scripts empty except for the input we are signing. In the case
            // where addInput has been used to set up a new transaction, they are already all empty. The input being signed
            // has to have the connected OUTPUT program in it when the hash is calculated!
            //
            // Note that each input may be claiming an output sent to a different key. So we have to look at the outputs
            // to figure out which key to sign with.

            KeyBag maybeDecryptingKeyBag = new DecryptingKeyBag(_wallet, _sendRequest.aesKey);

            // clear all the input scripts, if there were any.
            // in SigAll hash mode, you sign such that all inputs are cleared (it would be impossible to sign otherwise
            // since the signatures end up in the input scriptSig).  Except for the quirk later on in this code
            // where we copy in the scriptPub of the connected output into the input.
            int numInputs = inputs.size();
            for (int i = 0; i < numInputs; i++) {

                // Wallet.java will only clear the input script if it is not already signed, but
                // in our case we are the only signer so we can just start by clearing all of them
                TransactionInput input = inputs.get(i);
                input.setScriptSig(new Script(TransactionInput.EMPTY_ARRAY));
            }

            if (Constants.TRANSACTION_LOGGING) {
                String postRemovalSerializedTransaction = Util.bytesToHex(getSerializedTransaction());
                _logger.error(String.format("Serialized transaction after removing all inputs: transaction=%s", postRemovalSerializedTransaction));
            }

            // Adapted from LocalTransactionSigner.java

            // Determine all the hashes that we need to sign.
            // No talking to the smart card yet, just do the on device hashing
            for (int i = 0; i < numInputs; i++) {

                if (this.isCancelled()) {
                    resultCode = SecureElementTransactionSigner.CANCELED;
                    break;
                }

                TransactionInput txIn = inputs.get(i);
                // We don't have the connected output, we assume it was signed already and move on
                if (txIn.getConnectedOutput() == null) {
                    _logger.warn("signTransaction: Missing connected output, assuming txIn {} is already signed.", i);
                    continue;
                }

                try {
                    // We assume if its already signed, its hopefully got a SIGHASH type that will not invalidate when
                    // we sign missing pieces (to check this would require either assuming any signatures are signing
                    // standard output types or a way to get processed signatures out of script execution)
                    txIn.getScriptSig().correctlySpends(_transaction, i, txIn.getConnectedOutput().getScriptPubKey());
                    _logger.warn("signTransaction: Input {} already correctly spends output, assuming SIGHASH type used will be safe and skipping signing.", i);
                    continue;
                } catch (ScriptException e) {
                    // Expected.
                }

                if (txIn.getScriptBytes().length != 0) {
                    _logger.warn("signTransaction: Re-signing an already signed transaction! Be sure this is what you want.");
                }

                RedeemData redeemData = txIn.getConnectedRedeemData(maybeDecryptingKeyBag);

                // For P2SH inputs we need to share derivation path of the signing key with other signers, so that they
                // use correct key to calculate their signatures.
                // Married keys all have the same derivation path, so we can safely just take first one here.
                ECKey pubKey = redeemData.keys.get(0);
                if (pubKey instanceof DeterministicKey) {

                    DeterministicKey deterministicKey = (DeterministicKey)pubKey;

                    ImmutableList<ChildNumber> childPath = deterministicKey.getPath();
                    ChildNumber childNumber = deterministicKey.getChildNumber();

                    if(childPath.size() != 3) {
                        throw new IOException("invalid child key path size");
                    }

                    DeterministicKey parent = ((DeterministicKey) pubKey).getParent();

                    ImmutableList<ChildNumber> parentPath = parent.getPath();

                    if(parentPath.size() != 2) {
                        throw new IOException("invalid parent key path size");
                    }
                    ChildNumber parentChildNumber = parent.getChildNumber();
                    int parentChildI = parentChildNumber.getI();
                    if (parentChildI == 0) {
                        _parentKeySlots[i] = 2;
                    } else if (parentChildI == 1) {
                        _parentKeySlots[i] = 3;
                    }  else {
                        throw new IOException("invalid parent child i");
                    }

                    byte [] parentPublicKey = parent.getPubKey();

                    assert parentPublicKey.length == 33 : parentPublicKey.length;

                    ByteBuffer data = ByteBuffer.allocate(37);
                    data.put(parentPublicKey);
                    data.putInt(childNumber.i());
                    byte[] toAdd = HDUtils.hmacSha512(parent.getChainCode(), data.array());

                    _logger.info( "length of i=" + toAdd.length);
                    if (toAdd == null || toAdd.length != 64) {
                        throw new IOException("incorrect toAdd length");
                    }

                    byte [] beginningOfToAdd = Arrays.copyOfRange( toAdd, 0, 32);
                    if (beginningOfToAdd.length != 32) {
                        throw new IOException("incorrect beginningOfToAdd length");
                    }

                    // Store the first 32 bytes of the toAdd, we'll need it later to send to the card to do this signing.
                    _beginningOfToAdds[i] = beginningOfToAdd;

                } else {
                    throw new IOException("pubKey not a DeterministicKey");
                }

                // script here would be either a standard CHECKSIG program for pay-to-address or pay-to-pubkey inputs or
                // a CHECKMULTISIG program for P2SH inputs
                byte[] script = redeemData.redeemScript.getProgram();

                // Find the signing key we'll need to use.
                // find the key in the local cached wallet that matches this (note the local cached wallet only has the public key)
                ECKey key = txIn.getOutpoint().getConnectedKey(_wallet);
                // This assert should never fire. If it does, it means the wallet is inconsistent.
                checkNotNull(key, "signTransaction: Transaction exists in wallet that we cannot redeem: %s", txIn.getOutpoint().getHash());
                // Keep the key around for the script creation step below.
                _signingKeys[i] = key;

                // Adapted from Transaction.java

                // This step has no purpose beyond being synchronized with the reference clients bugs. OP_CODESEPARATOR
                // is a legacy holdover from a previous, broken design of executing scripts that shipped in Bitcoin 0.1.
                // It was seriously flawed and would have let anyone take anyone elses money. Later versions switched to
                // the design we use today where scripts are executed independently but share a stack. This left the
                // OP_CODESEPARATOR instruction having no purpose as it was only meant to be used internally, not actually
                // ever put into scripts. Deleting OP_CODESEPARATOR is a step that should never be required but if we don't
                // do it, we could split off the main chain.
                script = Script.removeAllInstancesOfOp(script, ScriptOpCodes.OP_CODESEPARATOR);

                // Set the txIn to the script of its output. Satoshi does this but the step has no obvious purpose as
                // the signature covers the hash of the prevout transaction which obviously includes the output script
                // already. Perhaps it felt safer to him in some way, or is another leftover from how the code was written.
                // inputs.get(i).setScriptBytes(connectedPubKeyScript);
                txIn.setScriptSig(new Script(script));

                ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(256);
                _transaction.bitcoinSerialize(bos);
                // We also have to write a hash type (sigHashType is actually an unsigned char)
                byte sigHashType = (byte)TransactionSignature.calcSigHashValue(Transaction.SigHash.ALL, false);
                uint32ToByteStreamLE(0x000000ff & sigHashType, bos);
                // Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
                // however then we would expect that it is IS reversed.

                // we have the bytes to sign
                byte[] bytesToSignNonHashed = bos.toByteArray();
                bos.close();

                if (Constants.TRANSACTION_LOGGING) {
                    String serializedTransactionString = Util.bytesToHex(getSerializedTransaction());
                    _logger.error(String.format("Serialized transaction after adding unsigned input index=%d, transaction=%s", i, serializedTransactionString));
                }

                // Note: Transaction.java does a double digest but we only single digest because the card
                // will do the second digest
               _dataToSign[i] = Utils.singleDigest( bytesToSignNonHashed, 0, bytesToSignNonHashed.length);

                // Put the transaction back to how we found it, which is empty (since we set
                // all the scripts to empty in our first loop
                //inputs.get(i).setScriptBytes(TransactionInput.EMPTY_ARRAY);
                txIn.setScriptSig(new Script(TransactionInput.EMPTY_ARRAY));
            }

            _logger.info("signTransaction: beginning secure element signing loop");
            // Now get the secure element to sign all the data
            // start from where we last left off
            for (int i = _currentInputIndex; i < _dataToSign.length; i++) {
                if (this.isCancelled()) {
                    resultCode = SecureElementTransactionSigner.CANCELED;
                    break;
                }

                // we didn't get a cached signature
                // now sign with the smart card - it will hash the bytes a second time
                // before actually signing, which is what we want because that's what bitcoin does- double hashed signature
                _logger.info("signTransaction: signing with secure element for input index " + i);
                byte[] signatureFromSecureElement = secureElementApplet.doSimpleSign( _parentKeySlots[i], _beginningOfToAdds[i], _dataToSign[i], _antiMalwareKey);

                ECKey.ECDSASignature ecdsaSignature = ECKey.ECDSASignature.decodeFromDER(signatureFromSecureElement);

                _signatures[i] = new TransactionSignature(ecdsaSignature, Transaction.SigHash.ALL, false);

                _currentInputIndex++; // mark that we've signed for one of the inputs - in case the connection gets broken

                publishProgress((int)((_currentInputIndex / (float)_dataToSign.length) * 100));
            }

            // Now we have calculated each signature, go through and create the scripts. Reminder: the script consists:
            // 1) For pay-to-address outputs: a signature (over a hash of the simplified transaction) and the complete
            //    public key needed to sign for the connected output. The output script checks the provided pubkey hashes
            //    to the address and then checks the signature.
            // 2) For pay-to-key outputs: just a signature.
            for (int i = 0; i < inputs.size(); i++) {
                if (this.isCancelled()) {
                    resultCode = SecureElementTransactionSigner.CANCELED;
                    break;
                }

                if (_signatures[i] == null) {
                    continue;
                }

                TransactionInput input = inputs.get(i);
                final TransactionOutput connectedOutput = input.getOutpoint().getConnectedOutput();
                checkNotNull(connectedOutput);  // Quiet static analysis: is never null here but cannot be statically proven
                Script scriptPubKey = connectedOutput.getScriptPubKey();
                if (scriptPubKey.isSentToAddress()) {
                    input.setScriptSig(ScriptBuilder.createInputScript(_signatures[i], _signingKeys[i]));
                } else if (scriptPubKey.isSentToRawPubKey()) {
                    input.setScriptSig(ScriptBuilder.createInputScript(_signatures[i]));
                } else {
                    // Should be unreachable - if we don't recognize the type of script we're trying to sign for, we should
                    // have failed above when fetching the key to sign with.
                    throw new RuntimeException("Do not understand script type: " + scriptPubKey);
                }

                if (Constants.TRANSACTION_LOGGING) {
                    String serializedTransactionString = Util.bytesToHex(getSerializedTransaction());
                    _logger.error(String.format("Serialized transaction after adding signed input index=%d, transaction=%s", i, serializedTransactionString));
                }
            }

            if (Constants.TRANSACTION_LOGGING) {
                String serializedTransactionString = Util.bytesToHex(getSerializedTransaction());
                _logger.error(String.format("Final Serialized transaction=%s", serializedTransactionString));
            }

            _logger.info("signTransaction: successfully signed transaction");
        } catch (TagLostException e) {
            _logger.info("signTransaction: got TagLostException");
            resultCode = SecureElementTransactionSigner.TAG_LOST;
        } catch (IOException e) {
            _logger.error("signTransaction: got IOException: " + e.toString());
            resultCode = SecureElementTransactionSigner.ERROR;
        }

        return resultCode;
	}

    private byte [] getSerializedTransaction() throws IOException {

        ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(256);
        _transaction.bitcoinSerialize(bos);
        // We also have to write a hash type (sigHashType is actually an unsigned char)
        byte sigHashType = (byte)TransactionSignature.calcSigHashValue(Transaction.SigHash.ALL, false);
        uint32ToByteStreamLE(0x000000ff & sigHashType, bos);
        // Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
        // however then we would expect that it is IS reversed.

        // we have the bytes to sign
        byte[] serializedTransaction = bos.toByteArray();
        bos.close();

        return serializedTransaction;
    }

    @Override
    protected void onProgressUpdate(Integer... progress) {
        _logger.info("onProgressUpdate: " + progress[0]);
    	_listener.secureElementTransactionSignerProgress(progress[0]);
    }
	
	public int getProgress() {
		return (int)((_currentInputIndex / (float)getNumInputs()) * 100);
	}
	
    @Override
    protected void onPostExecute(Integer result) {
        _logger.info("onPostExecute: " + result);
    	_listener.secureElementTransactionListenerSignerFinished(result);
    }
}
