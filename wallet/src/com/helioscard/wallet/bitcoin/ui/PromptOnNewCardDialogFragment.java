package com.helioscard.wallet.bitcoin.ui;

import java.util.List;

import android.app.AlertDialog;
import android.app.Dialog;
import android.app.DialogFragment;
import android.app.FragmentManager;
import android.content.DialogInterface;
import android.os.Bundle;
import com.helioscard.wallet.bitcoin.Constants;
import com.helioscard.wallet.bitcoin.IntegrationConnector;
import com.helioscard.wallet.bitcoin.R;
import com.helioscard.wallet.bitcoin.secureelement.ECKeyEntry;
import com.helioscard.wallet.bitcoin.wallet.WalletGlobals;

//import com.google.bitcoin.core.ECKey;
//import com.google.bitcoin.core.Wallet;

import de.schildbach.wallet.AddressBookProvider;

public class PromptOnNewCardDialogFragment extends DialogFragment {
    public static final String TAG = "PromptOnNewCardDialogFragment";

    public static final String FIELD_TYPE = "type";
    public static final String FIELD_ORIGINAL = "original";
    public static final String FIELD_CARD_BEING_SWITCHED_TO = "card_being_switched_to";

    private int _type;
    private String _originalCardIdentifier;
    private String _cardBeingPromptedToSwitchToIdentifier;
//    private List<ECKeyEntry> _ecPublicKeyEntries;
    
    public static final int TYPE_NEW_CARD = 0;
    public static final int TYPE_SAVE_SUCCESSFUL = 1;

    public PromptOnNewCardDialogFragment() {
    }

//    public PromptOnNewCardDialogFragment(int type, String originalCardIdentifier, String cardBeingPromptedToSwitchToIdentifier, List<ECKeyEntry> ecPublicKeyEntries) {
//    	_type = type;
//    	_originalCardIdentifier = originalCardIdentifier;
//    	_cardBeingPromptedToSwitchToIdentifier = cardBeingPromptedToSwitchToIdentifier;
//    	_ecPublicKeyEntries = ecPublicKeyEntries;
//    }

	public static void prompt(FragmentManager fragmentManager, int type, String originalCardIdentifier, String cardBeingPromptedToSwitchToIdentifier ) {//}, List<ECKeyEntry> ecPublicKeyEntries) {
//		PromptOnNewCardDialogFragment frag = new PromptOnNewCardDialogFragment(type, originalCardIdentifier, cardBeingPromptedToSwitchToIdentifier, ecPublicKeyEntries);
        PromptOnNewCardDialogFragment frag = new PromptOnNewCardDialogFragment();

        Bundle args = new Bundle();
        args.putInt(FIELD_TYPE, type);
        args.putString(FIELD_ORIGINAL, originalCardIdentifier);
        args.putString(FIELD_CARD_BEING_SWITCHED_TO, cardBeingPromptedToSwitchToIdentifier);

        frag.setArguments(args);

        frag.show(fragmentManager, TAG);
	}
	
	public String getCardBeingPromptedToSwitchToIdentifier() {
		return _cardBeingPromptedToSwitchToIdentifier;
	}
	
	@Override
    public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setRetainInstance(true); // retain instance so we keep the list of keys
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
    	final NFCAwareActivity nfcAwareActivity = (NFCAwareActivity)getActivity();
    	
		AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(nfcAwareActivity);

        Bundle bundle = getArguments();
        _type = bundle.getInt(FIELD_TYPE);
    	_originalCardIdentifier = bundle.getString(FIELD_ORIGINAL);
    	_cardBeingPromptedToSwitchToIdentifier = bundle.getString(FIELD_CARD_BEING_SWITCHED_TO);

		String alertMessage = String.format(getResources().getString(_type == TYPE_NEW_CARD ? R.string.nfc_aware_activity_prompt_on_new_card_dialog_message : R.string.nfc_aware_activity_prompt_on_new_card_dialog_save_successful), _originalCardIdentifier, _cardBeingPromptedToSwitchToIdentifier);
//		int numKeys = _ecPublicKeyEntries.size();
//		alertMessage += "\n\n";
//		if (numKeys > 0) {
//			alertMessage += String.format(getResources().getString(R.string.nfc_aware_activity_prompt_on_new_card_dialog_message_contains_keys), _cardBeingPromptedToSwitchToIdentifier);
//			for (int i = 0; i < numKeys; i++) {
//				ECKeyEntry ecKeyEntry = _ecPublicKeyEntries.get(i);
//				String label = ecKeyEntry.getFriendlyName();
//				if (label == null || label.isEmpty()) {
//					label = getResources().getString(R.string.nfc_aware_activity_prompt_on_new_card_dialog_message_unlabeled);
//				}
//
//				alertMessage += "\n---------------\n";
//				alertMessage += String.format(getResources().getString(R.string.nfc_aware_activity_choose_keys_to_backup_dialog_label), label, new ECKey(null, ecKeyEntry.getPublicKeyBytes()).toAddress(Constants.NETWORK_PARAMETERS));
//			}
//		} else {
//			alertMessage += String.format(getResources().getString(R.string.nfc_aware_activity_prompt_on_new_card_dialog_message_no_keys), _cardBeingPromptedToSwitchToIdentifier);
//		}
//
//		alertMessage += "\n\n";
		
		// Now show the user the keys on the current card
//		Wallet wallet = IntegrationConnector.getWallet(nfcAwareActivity);
//		List<ECKey> keysInWallet = wallet.getKeys();
//		numKeys = keysInWallet.size();
//		if (numKeys > 0) {
//			alertMessage += String.format(getResources().getString(R.string.nfc_aware_activity_prompt_on_new_card_dialog_message_contains_keys_current), _originalCardIdentifier);
//			for (ECKey ecKeyInWallet : keysInWallet) {
//				String addressString = ecKeyInWallet.toAddress(Constants.NETWORK_PARAMETERS).toString();
//				String label = AddressBookProvider.resolveLabel(nfcAwareActivity, addressString);
//				if (label == null || label.isEmpty()) {
//					label = getResources().getString(R.string.nfc_aware_activity_prompt_on_new_card_dialog_message_unlabeled);
//				}
//				alertMessage += "\n---------------\n";
//				alertMessage += String.format(getResources().getString(R.string.nfc_aware_activity_choose_keys_to_backup_dialog_label), label, addressString);
//			}
//		} else {
//			alertMessage += String.format(getResources().getString(R.string.nfc_aware_activity_prompt_on_new_card_dialog_message_no_keys_current), _originalCardIdentifier);
//		}
		
		alertDialogBuilder.setMessage(alertMessage);
//
		alertDialogBuilder.setTitle(getResources().getString(_type == TYPE_NEW_CARD ? R.string.nfc_aware_activity_prompt_on_new_card_dialog_title : R.string.nfc_aware_activity_prompt_on_new_card_dialog_title_save_successful));
        alertDialogBuilder.setPositiveButton(getResources().getString(R.string.nfc_aware_activity_prompt_for_backup_or_restore_dialog_title), new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int id) {
				dialog.dismiss();
//				((NFCAwareActivity)getActivity()).promptForBackupOrRestore();
			}
		});
		alertDialogBuilder.setNegativeButton(getResources().getString(R.string.helioscard_cancel), new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int id) {
				// if this button is clicked, just close
				// the dialog box and do nothing
				dialog.cancel();
				((NFCAwareActivity)getActivity()).resetState();
			  }
		});
       
        // prevent us from being cancelable via the back button or clicking outside the bounds of the dialog
        this.setCancelable(false);

        return alertDialogBuilder.create();
    }
    
}
