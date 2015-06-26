package com.helioscard.wallet.bitcoin.wallet;


import android.app.Activity;
import android.app.Service;
import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WalletGlobals {
	private static WalletGlobals _walletGlobals;

    private static final String PREFERENCES_FIELD_CARD_IDENTIFIER = "HeliosCardCurrentCardIdentifier";
    private static final String PREFERENCES_ANTI_MALWARE_IDENTIFIER = "HeliosCardAntiMalwareKey";
    private static final String PREFERENCES_FIELD_SERVICE_NEEDS_TO_REPLAY_BLOCKCHAIN = "HeliosCardServiceNeedsToReplayBlockChain";
	
    private static Logger _logger = LoggerFactory.getLogger(WalletGlobals.class);
    
	private String _cardIdentifier;
	private String _antiMalwareKey;

	public static WalletGlobals getInstance(Context context) {
		if (_walletGlobals == null) {
			_walletGlobals = new WalletGlobals(context);
		}
		return _walletGlobals;
	}
	
	public WalletGlobals(Context context) {
		Context baseContext = null;
		if (context instanceof Activity) {
			baseContext = ((Activity)context).getBaseContext();
		} else if (context instanceof Service) {
			baseContext = ((Service)context).getBaseContext();
		}
		
		SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(baseContext);
        // read the last card identifier we used
        _cardIdentifier = sharedPreferences.getString(PREFERENCES_FIELD_CARD_IDENTIFIER, null);
        _logger.info("read cached cardIdentifier: " + _cardIdentifier);
		if (_cardIdentifier == null) {
			// the wallet isn't initialized yet
			_logger.info("no card identifier");
		}

        // read the last anti-malware key we used
        _antiMalwareKey = sharedPreferences.getString(PREFERENCES_ANTI_MALWARE_IDENTIFIER, null);
        if (_antiMalwareKey == null) {
            _logger.info("no anti-malware key set");
        }
	}
	
	public String getCardIdentifier() {
		return _cardIdentifier;
	}

    public boolean setCardIdentifier(Context context, String cardIdentifier) {
        // we might be switching cards, clear out the old wallet
        if (_cardIdentifier != null && _cardIdentifier.equals(cardIdentifier)) {
            _logger.info("setCardIdentifier: ignoring setCardIdentifier, already matches");
            return false;
        }

        _logger.info("setCardIdentifier: changing card identifier to: " + cardIdentifier);

        boolean cardIdentifierWasChanged = (_cardIdentifier != null);
        _cardIdentifier = cardIdentifier;

        // update the last known card identifier, so we can re-use next time if we're reloaded without the wallet
        // app being explicitly tapped by a card
		Context baseContext = null;
		if (context instanceof Activity) {
			baseContext = ((Activity)context).getBaseContext();
		} else if (context instanceof Service) {
			baseContext = ((Service)context).getBaseContext();
		}

        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(baseContext);
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(PREFERENCES_FIELD_CARD_IDENTIFIER, _cardIdentifier);
        editor.commit();
        return cardIdentifierWasChanged;
    }

	public boolean isAntiMalwareKeySet() {
		return _antiMalwareKey != null;
	}

	public String getAntiMalwareKey() {
		return _antiMalwareKey;
	}

	public boolean setAntiMalwareKey(Context context, String antiMalwareKey) {

		boolean antiMalwareKeyChanged = (_antiMalwareKey != null);
        _antiMalwareKey = antiMalwareKey;

		// update the last known card identifier, so we can re-use next time if we're reloaded without the wallet
		// app being explicitly tapped by a card
		Context baseContext = null;
		if (context instanceof Activity) {
			baseContext = ((Activity)context).getBaseContext();
		} else if (context instanceof Service) {
			baseContext = ((Service)context).getBaseContext();
		}

		SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(baseContext);
		SharedPreferences.Editor editor = sharedPreferences.edit();
		editor.putString(PREFERENCES_ANTI_MALWARE_IDENTIFIER, _antiMalwareKey);
		editor.commit();
		return antiMalwareKeyChanged;
	}

//
//	public static void persistServiceNeedsToReplayBlockchain(Activity activityContext) {
//		// Call this method to indicate the contents of the wallet are about to change, and that we need to ensure
//		// that the service clears the blockchain and replays it.  This is to prevent an interruption where we change the
//		// wallet and then we reset the device before we can tell the service to delete the blockchain.  On service startup,
//		// the service should check to see whether the block chain needs to be replayed, and if so, replay it and clear this flag
//        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(activityContext.getBaseContext());
//        SharedPreferences.Editor editor = sharedPreferences.edit();
//        editor.putBoolean(PREFERENCES_FIELD_SERVICE_NEEDS_TO_REPLAY_BLOCKCHAIN, true);
//        editor.commit();
//
//    	Wallet wallet = IntegrationConnector.getWallet(activityContext);
//    	wallet.clearTransactions(0);
//    	wallet.setLastBlockSeenHeight(-1); // magic value
//    	wallet.setLastBlockSeenHash(null);
//	}
//
//	public static void resetServiceNeedsToReplayBlockchain(Context context) {
//		Context baseContext = null;
//		if (context instanceof Activity) {
//			baseContext = ((Activity)context).getBaseContext();
//		} else if (context instanceof Service) {
//			baseContext = ((Service)context).getBaseContext();
//		}
//
//		SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(baseContext);
//        SharedPreferences.Editor editor = sharedPreferences.edit();
//        editor.putBoolean(PREFERENCES_FIELD_SERVICE_NEEDS_TO_REPLAY_BLOCKCHAIN, false);
//        editor.commit();
//	}
//
//	public static boolean getServiceNeedsToReplayBlockchain(Context context) {
//		Context baseContext = null;
//		if (context instanceof Activity) {
//			baseContext = ((Activity)context).getBaseContext();
//		} else if (context instanceof Service) {
//			baseContext = ((Service)context).getBaseContext();
//		}
//
//        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(baseContext);
//        // read the last card identifier we used
//        return sharedPreferences.getBoolean(PREFERENCES_FIELD_SERVICE_NEEDS_TO_REPLAY_BLOCKCHAIN, false);
//	}
//
}
