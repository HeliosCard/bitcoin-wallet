package com.helioscard.wallet.bitcoin.ui;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;

import com.helioscard.wallet.bitcoin.R;

public class PromptForGetStartedDialogFragment extends DialogFragment {
    public static final String TAG = "PromptForGetStartedDialogFragment";

	public static void prompt(FragmentManager fragmentManager) {
		PromptForGetStartedDialogFragment frag = new PromptForGetStartedDialogFragment();
    	frag.show(fragmentManager, TAG);
	}

    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
    	final NFCAwareActivity nfcAwareActivity = (NFCAwareActivity)getActivity();
    	
		AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(nfcAwareActivity);
		alertDialogBuilder.setMessage(getResources().getString(R.string.nfc_aware_activity_get_started_dialog_message));
        alertDialogBuilder.setTitle(getResources().getString(R.string.nfc_aware_activity_get_started_dialog_title));
        alertDialogBuilder.setNegativeButton(getResources().getString(R.string.nfc_aware_activity_get_started_dialog_create_new_key), null);
//todo: add back when we add b/r
//        alertDialogBuilder.setPositiveButton(getResources().getString(R.string.nfc_aware_activity_prompt_for_backup_or_restore_dialog_title), null);
        
        // prevent us from being cancelable, we want to force the user to create or import a key
//todo: add back in once this dialog is complete, for now it doesn't do anything useful
//        this.setCancelable(false);

        final AlertDialog alertDialog = alertDialogBuilder.create();
        
        // override the buttons this way so that we prevent the dialog from closing when the user hits the buttons
        alertDialog.setOnShowListener(new DialogInterface.OnShowListener() {
            @Override
            public void onShow(DialogInterface dialog) {

//todo: add when we support b/r
                Button b = alertDialog.getButton(AlertDialog.BUTTON_POSITIVE);
//                b.setOnClickListener(new View.OnClickListener() {
//                    @Override
//                    public void onClick(View view) {
//        				// dialog.dismiss(); // don't dismiss ourselves - we'll get dismissed once the user has a key
//        				((NFCAwareActivity)getActivity()).promptForBackupOrRestore();
//                        alertDialog.cancel();
//                    }
//                });

                b = alertDialog.getButton(AlertDialog.BUTTON_NEGATIVE);
                b.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View view) {
        				// dialog.dismiss(); // don't dismiss ourselves - we'll get dismissed once the user has a key
//        				((NFCAwareActivity)getActivity()).promptToAddKey();
        				((NFCAwareActivity)getActivity()).setupCardPrePreTap();
//                        alertDialog.dismiss();
                    }
                });

            }
        });

        return alertDialog;
    }
    
}
