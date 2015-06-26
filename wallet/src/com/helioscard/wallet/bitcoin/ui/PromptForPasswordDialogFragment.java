package com.helioscard.wallet.bitcoin.ui;

import java.io.IOException;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.DialogInterface;
import android.os.Bundle;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.view.KeyEvent;
import android.view.View;
import android.view.View.OnKeyListener;
import android.widget.EditText;

import com.helioscard.wallet.bitcoin.R;
import com.helioscard.wallet.bitcoin.secureelement.SecureElementApplet;

public class PromptForPasswordDialogFragment extends DialogFragment {
    public static final String TAG = "PromptForPasswordDialogFragment";
    
    private AlertDialog _alertDialog;
    
    private static final String FIELD_TYPE = "type";

    public static final int TYPE_NORMAL = 0;
    public static final int TYPE_BACKUP = 1;
    public static final int TYPE_SAVE_KEYS_TO_CARD = 2;

    
	public static void prompt(FragmentManager fragmentManager, int type) {
		PromptForPasswordDialogFragment frag = new PromptForPasswordDialogFragment();
		Bundle args = new Bundle();
		args.putInt(FIELD_TYPE, type);
		frag.setArguments(args);
    	frag.show(fragmentManager, TAG);
	}

	@Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
    	final NFCAwareActivity nfcAwareActivity = (NFCAwareActivity)getActivity();
    	
    	int type = getArguments().getInt(FIELD_TYPE);
    	
		AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(nfcAwareActivity);
		 
		String alertDialogTitle;
		if (type == TYPE_BACKUP) {
			alertDialogTitle = getResources().getString(R.string.nfc_aware_activity_prompt_for_password_title_backup_card_text); 			
		} else if (type == TYPE_SAVE_KEYS_TO_CARD) {
			alertDialogTitle = getResources().getString(R.string.nfc_aware_activity_prompt_for_password_title_save_keys_to_card);			
		} else {
			alertDialogTitle = getResources().getString(R.string.nfc_aware_activity_prompt_for_password_title);			
		}
		// set title
		alertDialogBuilder.setTitle(alertDialogTitle);

		// Set an EditText view to get user input
		final EditText input = new EditText(nfcAwareActivity);
		input.setSingleLine(true);
		// Make it a password entry field
		input.setTransformationMethod(PasswordTransformationMethod.getInstance());
		input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
		
		/*
		InputFilter[] filterArray = new InputFilter[1];
		// TODO: using this input filter is preventing the use of the backspace key once you've typed 8 characters
		// use a different system to prevent more than 8 characters
		filterArray[0] = new InputFilter.LengthFilter(8); // 8 characters at most
		input.setFilters(filterArray);
		*/

		alertDialogBuilder.setView(input);

	    // set dialog message
		alertDialogBuilder
			.setCancelable(false)
			.setPositiveButton(getResources().getString(R.string.helioscard_ok), new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int id) {
					// now try to login to the card
					dialog.dismiss();
					((NFCAwareActivity)getActivity()).userProceededOnPasswordDialog(input.getText().toString());
				  }
				})
			.setNegativeButton(getResources().getString(R.string.helioscard_cancel), new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int id) {
					// if this button is clicked, just close
					// the dialog box and do nothing
					dialog.cancel();
					((NFCAwareActivity)getActivity()).resetState();
				  }
				});

		_alertDialog = alertDialogBuilder.create();
 		generatePasswordAttemptsLeftText();

		// Make it pressing enter on the confirm new password field will try to initialize the card
		input.setOnKeyListener(new OnKeyListener() {
		    public boolean onKey(View v, int keyCode, KeyEvent event) {
		        if(keyCode == KeyEvent.KEYCODE_ENTER && event.getAction() == KeyEvent.ACTION_UP) {
		        	_alertDialog.dismiss();
		        	((NFCAwareActivity)getActivity()).userProceededOnPasswordDialog(input.getText().toString());
		        	return true;
		        }
		        return false;
		    }
		});

		
		this.setCancelable(false); // prevent the user from using the back button to dismiss this dialog
		
		// create alert dialog and show it
		return _alertDialog;
    }

	public void generatePasswordAttemptsLeftText() {
    	final NFCAwareActivity nfcAwareActivity = (NFCAwareActivity)getActivity();
		
		int passwordAttemptsLeft = -1;
		SecureElementApplet secureElementApplet = nfcAwareActivity.getCachedSecureElementApplet();
		if (secureElementApplet != null) {
			// see if we know how many connection attempts are left because we're connected to the secure element
			try {
				passwordAttemptsLeft = secureElementApplet.getNumberPasswordAttemptsLeft();
			} catch (IOException e) {
			}
		}
    	int type = getArguments().getInt(FIELD_TYPE);		
		String alertDialogMessage;
		if (type == TYPE_BACKUP) {
			alertDialogMessage = getResources().getString(R.string.nfc_aware_activity_prompt_for_password_message_backup_card_text);
		} else if (type == TYPE_SAVE_KEYS_TO_CARD) {
			alertDialogMessage = getResources().getString(R.string.nfc_aware_activity_prompt_for_password_message_save_keys_to_card);
		} else {
			alertDialogMessage = getResources().getString(R.string.nfc_aware_activity_prompt_for_password_message);			
		}
		
		alertDialogMessage += " ";
		if (passwordAttemptsLeft == -1) {
			// we don't know how many password attempts left
			alertDialogMessage += getResources().getString(R.string.nfc_aware_activity_prompt_for_password_number_attempts_left_unknown); 
		} else if (passwordAttemptsLeft == 1) {
			alertDialogMessage += getResources().getString(R.string.nfc_aware_activity_prompt_for_password_number_attempts_warning_only_1_left);
		} else {
			String appendToAlertDialogMessage = String.format(getResources().getString(R.string.nfc_aware_activity_prompt_for_password_number_attempts_left), passwordAttemptsLeft);
			alertDialogMessage += appendToAlertDialogMessage;
		}
		
		_alertDialog.setMessage(alertDialogMessage);
	}

}
