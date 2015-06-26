package com.helioscard.wallet.bitcoin.ui;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.widget.CheckBox;

import com.helioscard.wallet.bitcoin.R;

public class EULAAndSafetyDialogFragment extends DialogFragment {
    public static final String TAG = "EULAAndSafetyDialogFragment";
    private static final String PREFERENCES_FIELD_SHOW_EULA_EVERY_TIME = "HeliosCardShowEULAEveryTime";

    private static boolean _displayedSinceAppStarted = false;
    
	public static void promptIfNeeded(FragmentManager fragmentManager, Activity activityContext) {
        SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(activityContext.getBaseContext());
		boolean shouldShowSharedPreferencesEveryTime = sharedPreferences.getBoolean(PREFERENCES_FIELD_SHOW_EULA_EVERY_TIME, true);
		
		if (shouldShowSharedPreferencesEveryTime && !_displayedSinceAppStarted) {
			// if the fragment is already showing, hide it, so that we can move a new one to the top
			EULAAndSafetyDialogFragment eulaAndSafetyDialogFragment = (EULAAndSafetyDialogFragment)fragmentManager.findFragmentByTag(TAG);
			if (eulaAndSafetyDialogFragment != null) {
				eulaAndSafetyDialogFragment.dismiss();
			}

			EULAAndSafetyDialogFragment frag = new EULAAndSafetyDialogFragment();
			frag.show(fragmentManager, TAG);
			
			_displayedSinceAppStarted = true;
		}
	}
	
	public static void prompt(FragmentManager fragmentManager) {
		EULAAndSafetyDialogFragment frag = new EULAAndSafetyDialogFragment();
		frag.show(fragmentManager, TAG);
		
		_displayedSinceAppStarted = true;
	}
	
    @Override
    public Dialog onCreateDialog(Bundle savedInstanceState) {
    	final Activity myActivity = getActivity();
    	
		AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(myActivity);
		 
		// set title
		String alertDialogTitle = getResources().getString(R.string.eula_and_safety_dialog_fragment_title);
		alertDialogBuilder.setTitle(alertDialogTitle);
 
		String alertDialogMessage = getResources().getString(R.string.eula_and_safety_dialog_fragment_message);

		SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(getActivity().getBaseContext());
		boolean shouldShowSharedPreferencesEveryTime = sharedPreferences.getBoolean(PREFERENCES_FIELD_SHOW_EULA_EVERY_TIME, true);
		final CheckBox checkBox = new CheckBox(myActivity);
		checkBox.setText(getResources().getString(R.string.eula_and_safety_dialog_fragment_display_every_time));
		checkBox.setChecked(shouldShowSharedPreferencesEveryTime);
		alertDialogBuilder.setView(checkBox);
		
		// set dialog message
		alertDialogBuilder
			.setMessage(alertDialogMessage)
			.setCancelable(false)
			.setPositiveButton(getResources().getString(R.string.eula_and_safety_dialog_fragment_i_agree), new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int id) {
					// if this button is clicked, just close
					// the dialog box and do nothing
					dialog.dismiss();

					SharedPreferences sharedPreferences = PreferenceManager.getDefaultSharedPreferences(getActivity().getBaseContext());
			        SharedPreferences.Editor editor = sharedPreferences.edit();
			        editor.putBoolean(PREFERENCES_FIELD_SHOW_EULA_EVERY_TIME, checkBox.isChecked());
			        editor.commit();
				}
				});

		this.setCancelable(false); // prevent the user from using the back button to dismiss this dialog
		
		// create alert dialog
		return alertDialogBuilder.create();
    }
}
