package com.helioscard.wallet.bitcoin.ui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helioscard.wallet.bitcoin.IntegrationConnector;
import com.helioscard.wallet.bitcoin.R;
import com.helioscard.wallet.bitcoin.secureelement.SecureElementApplet;

import android.content.Intent;
import android.os.Bundle;

public class MainActivity extends NFCAwareActivity {
	private static Logger _logger = LoggerFactory.getLogger(MainActivity.class);

	@Override
	protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        checkIfNFCRadioOnPromptUser(false);
	}

    @Override
    protected void handleCardDetected(SecureElementApplet secureElementApplet, boolean tapRequested, boolean authenticated, byte[] hashedPasswordBytes) {
        _logger.info("handleCardDetected: card was tapped");

        if( !showGetStartedDialogIfNeeded() ) {
            // launch the WalletActivity class and clear us off the stack
            Intent intent = new Intent(this, IntegrationConnector.WALLET_ACTIVITY_CLASS);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            this.finish();
        }
    }
}
