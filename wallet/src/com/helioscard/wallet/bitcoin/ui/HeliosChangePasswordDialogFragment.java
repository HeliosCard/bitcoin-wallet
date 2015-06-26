package com.helioscard.wallet.bitcoin.ui;

import com.helioscard.wallet.bitcoin.R;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnKeyListener;
import android.widget.EditText;
import android.widget.Toast;

public class HeliosChangePasswordDialogFragment extends DialogFragment {
    public static final String TAG = "HeliosChangePasswordDialogFragment";

    private EditText _firstPasswordField;
    private EditText _secondPasswordField;
    
	public static void prompt(FragmentManager fragmentManager) {
		HeliosChangePasswordDialogFragment frag = new HeliosChangePasswordDialogFragment();
    	frag.show(fragmentManager, TAG);
	}

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
    	final NFCAwareActivity nfcAwareActivity = (NFCAwareActivity)getActivity();
    	
        LayoutInflater inflater = nfcAwareActivity.getLayoutInflater();

        View view = inflater.inflate(R.layout.helios_change_password_dialog_fragment, null);

        _firstPasswordField = (EditText)view.findViewById(R.id.helios_change_password_dialog_fragment_new_password_edit_text);
        _secondPasswordField = (EditText)view.findViewById(R.id.helios_change_password_dialog_fragment_new_password_edit_text_confirm);

		AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(nfcAwareActivity);
		alertDialogBuilder.setTitle(getResources().getString(R.string.helios_change_password_dialog_fragment_title));
		alertDialogBuilder.setMessage(getResources().getString(R.string.helios_change_password_dialog_fragment_message));
		alertDialogBuilder.setView(view);

	    // set dialog message
		alertDialogBuilder
			.setCancelable(false)
			.setPositiveButton(getResources().getString(R.string.helioscard_ok), new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int id) {
					// now try to login to the card
					validatePassword(dialog);
				  }
				})
			.setNegativeButton(getResources().getString(R.string.helioscard_cancel), new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int id) {
					// if this button is clicked, just close
					// the dialog box and do nothing
					dialog.cancel();
					nfcAwareActivity.resetState();
				  }
				});

		final AlertDialog alertDialog = alertDialogBuilder.create();

		_secondPasswordField.setOnKeyListener(new OnKeyListener() {
		    public boolean onKey(View v, int keyCode, KeyEvent event) {
		        if(keyCode == KeyEvent.KEYCODE_ENTER && event.getAction() == KeyEvent.ACTION_UP) {
		        	validatePassword(alertDialog);
		        	return true;
		        }
		        return false;
		    }
		});
		
		// Make it pressing enter on the confirm new password field will try to initialize the card
		_firstPasswordField.setOnKeyListener(new OnKeyListener() {
		    public boolean onKey(View v, int keyCode, KeyEvent event) {
		        if(keyCode == KeyEvent.KEYCODE_ENTER && event.getAction() == KeyEvent.ACTION_UP) {
		        	_secondPasswordField.requestFocus();
		        	return true;
		        }
		        return false;
		    }
		});
		
		// prevent us from being cancelable, we want to force the user to create or import a key
        this.setCancelable(false);

        return alertDialog;
    }
    
    private void validatePassword(DialogInterface dialog) {
    	final NFCAwareActivity nfcAwareActivity = (NFCAwareActivity)getActivity();
    	String password1 = _firstPasswordField.getText().toString();
    	String password2 = _secondPasswordField.getText().toString();
    	if (password1 == null || password1.length() == 0) {
    		Toast.makeText(nfcAwareActivity, getResources().getString(R.string.helios_change_password_dialog_fragment_error_no_password_entered), Toast.LENGTH_LONG).show();
    		return;
    	}
    	
    	if (!password1.equals(password2)) {
    		Toast.makeText(nfcAwareActivity, getResources().getString(R.string.helios_change_password_dialog_fragment_error_passwords_do_not_match), Toast.LENGTH_LONG).show();
    		return;
    	}
    	    	
    	// passwords match - continue to get the current password
    	dialog.dismiss();    	

    	nfcAwareActivity.changePasswordPreTap(password1);
    }

}
