package com.helioscard.wallet.bitcoin.ui;

import android.app.Activity;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.app.ProgressDialog;
import android.os.Bundle;

import com.helioscard.wallet.bitcoin.R;

public class PleaseWaitDialogFragment extends DialogFragment {
    public static final String TAG = "PleaseWaitDialogFragment";

	public static final String FIELD_TYPE = "type";

	public static final int TYPE_NORMAL = 0;
	public static final int TYPE_CARD_SETUP = 1;


	public static PleaseWaitDialogFragment show(FragmentManager fragmentManager) {
		return show(fragmentManager, TYPE_NORMAL);
	}

    public static PleaseWaitDialogFragment show(FragmentManager fragmentManager, int type) {
		PleaseWaitDialogFragment frag = new PleaseWaitDialogFragment();

		Bundle arguments = new Bundle();
		arguments.putInt(FIELD_TYPE, type);
		frag.setArguments(arguments);

    	frag.show(fragmentManager, TAG);
    	return frag;
	}

	@Override
    public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setRetainInstance(true); // retain instance so we can be easily dismissed
	}

	@Override
	public void onDestroyView() {
		// we have retain instance state turned on, avoid having the dialog disappear on rotation
	    if (getDialog() != null && getRetainInstance()) {
	        getDialog().setDismissMessage(null);
	    }
	    super.onDestroyView();
	}

    
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
    	final Activity myActivity = getActivity();

		int type = getArguments().getInt(FIELD_TYPE);

		final ProgressDialog dialog = new ProgressDialog(myActivity);

		if (type==TYPE_CARD_SETUP) {
			dialog.setMessage(getResources().getString(R.string.please_wait_dialog_fragment_card_setup));
		} else {
			dialog.setMessage(getResources().getString(R.string.please_wait_dialog_fragment_please_wait));
		}

		dialog.setIndeterminate(true);
		dialog.setCancelable(false);
  
		this.setCancelable(false); // prevent the user from using the back button to dismiss this dialog
		
		// create alert dialog
		return dialog;
    }
}
