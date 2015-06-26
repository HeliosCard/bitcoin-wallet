package com.helioscard.wallet.bitcoin.ui;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.DialogInterface;
import android.os.Bundle;

import com.helioscard.wallet.bitcoin.R;

public class PromptForTapDialogFragment extends DialogFragment {
    public static final String TAG = "PromptForTapDialogFragment";

    public static final String FIELD_TYPE = "type";
    
    public static final int TYPE_NORMAL = 0;
    public static final int TYPE_REPOSITION = 1;
    public static final int TYPE_BACKUP = 2;
    public static final int TYPE_SAVE_KEYS_TO_CARD = 3;

	public static void prompt(FragmentManager fragmentManager, int type) {
		PromptForTapDialogFragment frag = new PromptForTapDialogFragment();
		
		Bundle arguments = new Bundle();
		arguments.putInt(FIELD_TYPE, type);
		frag.setArguments(arguments);
		
    	frag.show(fragmentManager, TAG);
	}

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
    	final NFCAwareActivity nfcAwareActivity = (NFCAwareActivity)getActivity();
    	
		AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(nfcAwareActivity);
		 
		int type = getArguments().getInt(FIELD_TYPE);
		
		// set title
		String alertDialogTitle;
		if (type == TYPE_BACKUP) {
			alertDialogTitle = getResources().getString(R.string.nfc_aware_activity_prompt_for_tap_dialog_title_backup_card_text);
		} else if (type == TYPE_SAVE_KEYS_TO_CARD) {
			alertDialogTitle = getResources().getString(R.string.nfc_aware_activity_prompt_for_tap_dialog_title_save_keys_to_card);
		} else {
			alertDialogTitle = getResources().getString(R.string.nfc_aware_activity_prompt_for_tap_dialog_title);
		}
		alertDialogBuilder.setTitle(alertDialogTitle);
 
		String alertDialogMessage;
		if (type == TYPE_REPOSITION) {
			alertDialogMessage = getResources().getString(R.string.nfc_aware_activity_prompt_for_tap_dialog_message_reposition);
		} else if (type == TYPE_BACKUP) {
			alertDialogMessage = getResources().getString(R.string.nfc_aware_activity_prompt_for_tap_dialog_message_backup_card_text);			
		} else if (type == TYPE_SAVE_KEYS_TO_CARD) {
			alertDialogMessage = getResources().getString(R.string.nfc_aware_activity_prompt_for_tap_dialog_message_save_keys_to_card);			
		} else {
			alertDialogMessage = getResources().getString(R.string.nfc_aware_activity_prompt_for_tap_dialog_message);
		}
		
			// set dialog message
		alertDialogBuilder
			.setMessage(alertDialogMessage)
			.setCancelable(false)
			.setNegativeButton(getResources().getString(R.string.helioscard_cancel), new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int id) {
					// if this button is clicked, just close
					// the dialog box and do nothing
					dialog.cancel();
					((NFCAwareActivity)getActivity()).resetState();
				  }
				});
 
		this.setCancelable(false); // prevent the user from using the back button to dismiss this dialog
		
		// create alert dialog
		return alertDialogBuilder.create();
    }
}
