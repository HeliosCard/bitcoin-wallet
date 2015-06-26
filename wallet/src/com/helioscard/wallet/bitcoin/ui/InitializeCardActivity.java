package com.helioscard.wallet.bitcoin.ui;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.helioscard.wallet.bitcoin.R;
import com.helioscard.wallet.bitcoin.secureelement.SecureElementApplet;

import android.os.Bundle;
import android.view.View;
import android.view.View.OnKeyListener;
import android.widget.EditText;
import android.view.KeyEvent;

public class InitializeCardActivity extends NFCAwareActivity {
	private static Logger _logger = LoggerFactory.getLogger(NFCAwareActivity.class);
	
	EditText _editTextInitializeCardEnterNewPassword;
	EditText _editTextInitializeCardConfirmNewPassword;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_initialize_card);
		
		_editTextInitializeCardEnterNewPassword = (EditText)findViewById(R.id.editTextInitializeCardEnterNewPassword);
		_editTextInitializeCardConfirmNewPassword = (EditText)findViewById(R.id.editTextInitializeCardConfirmNewPassword);

		// Make it so pressing enter on the enter new password field will move to the next field
		_editTextInitializeCardEnterNewPassword.setOnKeyListener(new OnKeyListener() {
		    public boolean onKey(View v, int keyCode, KeyEvent event) {
		        if(keyCode == KeyEvent.KEYCODE_ENTER && event.getAction() == KeyEvent.ACTION_UP) {
		        	_editTextInitializeCardConfirmNewPassword.requestFocus();
		        	return true;
		        }
		        return false;
		    }
		});

		// Make it pressing enter on the confirm new password field will try to initialize the card
		_editTextInitializeCardConfirmNewPassword.setOnKeyListener(new OnKeyListener() {
		    public boolean onKey(View v, int keyCode, KeyEvent event) {
		        if(keyCode == KeyEvent.KEYCODE_ENTER && event.getAction() == KeyEvent.ACTION_UP) {
		        	initializeCard();
		        	return true;
		        }
		        return false;
		    }
		});
		
		checkIfNFCRadioOnPromptUser(false);
	}

	public void buttonInitializeCardClickHandler(View v) {
		initializeCard();
	}
	
	private void initializeCard() {
        if (!checkIfNFCRadioOnPromptUser(true)) {
        	return;
        }
		
		// The user has entered the password and would like it accepted now.
		String firstPassword = _editTextInitializeCardEnterNewPassword.getText().toString();
		String secondPassword = _editTextInitializeCardConfirmNewPassword.getText().toString();

		if (firstPassword.equals("")) {
			// Require a password
			_editTextInitializeCardEnterNewPassword.setError(getString(R.string.initialize_card_no_password_entered));			
		} else if (!firstPassword.equals(secondPassword)) {
			// The passwords don't match - show a toast
			_editTextInitializeCardConfirmNewPassword.setError(getString(R.string.initialize_card_error_passwords_dont_match));
		} else {
			// The passwords matched - write them to the card
			// start by getting a connection to the secure element applet
			SecureElementApplet secureElementApplet = this.getSecureElementAppletPromptIfNeeded(false, true);
			if (secureElementApplet == null) {
				// the user wasn't holding the card to the phone, but now the user is being prompted to tap the card,
				// finish this operation later
				return;
			}
			changePasswordPostTap(secureElementApplet, SetPasswordOnCardAsyncTaskType.DOING_INITIALIZATION, null, firstPassword);
		}
	}
	
	@Override
	protected void handleCardDetected(SecureElementApplet secureElementApplet, boolean tapRequested, boolean authenticated, byte[] hashedPasswordBytes) {
		if (tapRequested) {
			// we are being called back because earlier the user had tried to set the password but
			// the card wasn't present, so we requested the user tap.  Now that the user has tapped, try to
			// set the password
			_logger.info("handleCardDetected: initializing card due to tapRequested");
			initializeCard();
		} else {
            _logger.info("handleCardDetected: tap not requested");
        }
	}
}
