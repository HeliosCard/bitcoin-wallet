package com.helioscard.wallet.bitcoin.ui;

import java.util.List;
import java.util.concurrent.RejectedExecutionException;

import android.app.Activity;
import android.app.Fragment;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.IBinder;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import com.helioscard.wallet.bitcoin.R;
import com.helioscard.wallet.bitcoin.wallet.WalletGlobals;

import org.bitcoinj.core.Peer;

public final class HeliosCardInfoFragment extends Fragment
{
	private de.schildbach.wallet.service.BlockchainService _blockChainService;
	
	private TextView _cardIdentifierTextView;
	private TextView _networkStatusTextView;
	
	@Override
	public View onCreateView(final LayoutInflater inflater, final ViewGroup container, final Bundle savedInstanceState)
	{
		return inflater.inflate(R.layout.helios_card_info_fragment, container, false);
	}

	@Override
	public void onViewCreated(final View view, final Bundle savedInstanceState)
	{
		super.onViewCreated(view, savedInstanceState);
		
		_cardIdentifierTextView = (TextView)view.findViewById(R.id.helios_card_info_fragment_card_identifier);
		_networkStatusTextView = (TextView)view.findViewById(R.id.helios_card_info_fragment_network_status);
	}
	
	@Override
	public void onDestroyView() {
		super.onDestroyView();
		_cardIdentifierTextView = null;
		_networkStatusTextView = null;
	}

	@Override
	public void onResume() {
		super.onResume();

		Activity attachedActivity = getActivity();
		attachedActivity.bindService(new Intent(attachedActivity, de.schildbach.wallet.service.BlockchainServiceImpl.class), _serviceConnection, Context.BIND_AUTO_CREATE);

		attachedActivity.registerReceiver(_broadcastReceiver, new IntentFilter(de.schildbach.wallet.service.BlockchainService.ACTION_PEER_STATE));
		
		updateView();
	}
	
	@Override
	public void onPause() {
		super.onPause();
		Activity attachedActivity = getActivity();
		attachedActivity.unbindService(_serviceConnection);
		attachedActivity.unregisterReceiver(_broadcastReceiver);
	}

	public void updateView() {
		WalletGlobals walletGlobals = WalletGlobals.getInstance(getActivity());
		String cardIdentifier = walletGlobals.getCardIdentifier();
		boolean isAntiMalwareKeySet = walletGlobals.isAntiMalwareKeySet();
		if (cardIdentifier != null) {
			_cardIdentifierTextView.setText(cardIdentifier + "  AM: " + (isAntiMalwareKeySet ? "Set" : "Not Set"));
		} else {
			_cardIdentifierTextView.setText("");
		}
	}

	private void updateNetworkStatus() {
		if (_blockChainService != null) {
			List<Peer> listOfPeers = _blockChainService.getConnectedPeers();
			if (listOfPeers != null && listOfPeers.size() > 0) {
				_networkStatusTextView.setText(getString(R.string.helios_card_info_fragment_card_connected_to_network));
			} else {
				_networkStatusTextView.setText(getString(R.string.helios_card_info_fragment_card_not_connected_to_network));				
			}
		}
	}

	private final BroadcastReceiver _broadcastReceiver = new BroadcastReceiver()
	{
		@Override
		public void onReceive(final Context context, final Intent intent)
		{
			try
			{
				updateNetworkStatus();
			}
			catch (final RejectedExecutionException x)
			{
			}
		}
	};

	
	private final ServiceConnection _serviceConnection = new ServiceConnection()
	{
		@Override
		public void onServiceConnected(final ComponentName name, final IBinder binder)
		{
			_blockChainService = ((de.schildbach.wallet.service.BlockchainServiceImpl.LocalBinder) binder).getService();
			updateNetworkStatus();
		}

		@Override
		public void onServiceDisconnected(final ComponentName name)
		{
			_blockChainService = null;
		}
	};

	
}
