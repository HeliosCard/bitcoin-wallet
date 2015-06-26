package com.helioscard.wallet.bitcoin;

import de.schildbach.wallet.ui.AddressBookActivity;
import de.schildbach.wallet.ui.WalletActivity;
import de.schildbach.wallet.ui.WalletAddressFragment;
import de.schildbach.wallet.ui.WalletAddressesFragment;
import de.schildbach.wallet.AddressBookProvider;
import de.schildbach.wallet.WalletApplication;

import android.app.Activity;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;

import android.support.v4.app.FragmentActivity;
import android.widget.Toast;

import com.helioscard.wallet.bitcoin.R;
import com.helioscard.wallet.bitcoin.ui.HeliosCardInfoFragment;

import org.bitcoinj.core.Wallet;

public class IntegrationConnector {
	public static final Class<WalletActivity> WALLET_ACTIVITY_CLASS = de.schildbach.wallet.ui.WalletActivity.class;

	
	public static Wallet getWallet(Activity activityContext) {
		return ((WalletApplication)activityContext.getApplication()).getWallet();
	}

	public static void ensureInfoFragmentIsUpdated(Activity activity) {
		HeliosCardInfoFragment infoFragment = (HeliosCardInfoFragment) activity.getFragmentManager().findFragmentById(R.id.helios_card_info_fragment);
		if (infoFragment != null) {
			infoFragment.updateView();
		}
	}

//
//	public static void ensureWalletAddressDisplayIsUpdated(FragmentActivity fragmentActivity) {
//		WalletAddressFragment walletAddressFragment = (WalletAddressFragment)fragmentActivity.getSupportFragmentManager().findFragmentById(R.id.wallet_address_fragment);
//		if (walletAddressFragment != null) {
//			walletAddressFragment.updateView();
//		}
//
//
//		// update the address book if we're showing it.  If it's a two pane view, we find it as below
//		WalletAddressesFragment walletAddressesFragment = (WalletAddressesFragment)fragmentActivity.getSupportFragmentManager().findFragmentById(R.id.wallet_addresses_fragment);
//		if (walletAddressesFragment != null) {
//			walletAddressesFragment.keysRemoved();
//		}
//
//		// if it's a one-pane view, we find it as below
//		walletAddressesFragment = (WalletAddressesFragment)fragmentActivity.getSupportFragmentManager().findFragmentByTag(AddressBookActivity.TAG_LEFT);
//		if (walletAddressesFragment != null) {
//			walletAddressesFragment.keysRemoved();
//		}
//	}
//
//	public static void deleteBlockchainAndRestartService(Activity activityContext) {
//		Toast.makeText(activityContext, activityContext.getResources().getString(R.string.nfc_aware_activity_resync_blockchain), Toast.LENGTH_LONG).show();
//		((WalletApplication)activityContext.getApplication()).resetBlockchain();
//	}

	public static void replaceWallet(Activity activityContext, Wallet newWallet) {
		((WalletApplication)activityContext.getApplication()).replaceWallet(newWallet);
	}

//
//	public static void setLabelForAddress(Context context, Address address, String newLabel) {
//		String addressString = address.toString();
//		final Uri uri = AddressBookProvider.contentUri(context.getPackageName()).buildUpon().appendPath(addressString).build();
//
//		final String label = AddressBookProvider.resolveLabel(context, addressString);
//
//		final boolean isAdd = label == null;
//
//		final ContentValues values = new ContentValues();
//		values.put(AddressBookProvider.KEY_LABEL, newLabel);
//
//		if (newLabel == null || newLabel.isEmpty()) {
//			if (!isAdd) {
//				context.getContentResolver().delete(uri,  null, null);
//			}
//		} else if (isAdd) {
//			context.getContentResolver().insert(uri, values);
//		} else {
//			if (!label.equals(newLabel)) {
//				context.getContentResolver().update(uri, values, null, null);
//			}
//		}
//	}
//
//	public static void backupWallet(Activity activity, String password, Wallet wallet) {
//		if (activity instanceof WalletActivity) {
//			((WalletActivity)activity).backupWallet(password, wallet);
//		}
//	}
//
//	public static void showRestoreWalletFromFileDialog(Activity activity) {
//		if (activity instanceof WalletActivity) {
//			((WalletActivity)activity).showDialog(WalletActivity.DIALOG_IMPORT_KEYS);
//		}
//	}
}
