package com.helioscard.wallet.bitcoin.ui;

import org.bitcoinj.core.Wallet;
import org.bitcoinj.crypto.DeterministicKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.FragmentManager;
import android.app.PendingIntent;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.TagLostException;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Parcelable;
import android.os.PatternMatcher;
import android.provider.Settings;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.widget.Toast;

import com.helioscard.wallet.bitcoin.IntegrationConnector;
import com.helioscard.wallet.bitcoin.R;
import com.helioscard.wallet.bitcoin.secureelement.SecureElementApplet;
import com.helioscard.wallet.bitcoin.secureelement.SmartCardReader;
import com.helioscard.wallet.bitcoin.secureelement.androidadapter.SmartCardReaderImpl;
import com.helioscard.wallet.bitcoin.secureelement.exception.CardWasWipedException;
import com.helioscard.wallet.bitcoin.secureelement.exception.KeyAlreadyExistsException;
import com.helioscard.wallet.bitcoin.secureelement.exception.SmartCardFullException;
import com.helioscard.wallet.bitcoin.secureelement.exception.WrongPasswordException;
import com.helioscard.wallet.bitcoin.secureelement.real.SecureElementAppletImpl;
import com.helioscard.wallet.bitcoin.wallet.WalletGlobals;

import java.io.IOException;

public abstract class NFCAwareActivity extends Activity {

    private static Logger _logger = LoggerFactory.getLogger(NFCAwareActivity.class);

    private NfcAdapter _nfcAdapter;
    private PendingIntent _pendingIntent;
    private IntentFilter[] _intentFiltersArray;

    private String _pendingCardPassword;
    private boolean _pendingUseExistingSessionIfPossible;
    private byte[] _pendingDeleteKeyPublicKeyBytes;
    private String _pendingChangePasswordNewPassword;
    private boolean _pendingBackupCard;
    private boolean _pendingSaveKeysToCard;
    private boolean _pendingGenerateSeed;
    private boolean _pendingGetData;
    private boolean _pendingSetupCard;
    private boolean _pendingWipe;

    public enum SetPasswordOnCardAsyncTaskType {
        NORMAL, DOING_RESTORE, DOING_INITIALIZATION
    }

    private static final String INSTANCE_STATE_PENDING_CARD_PASSWORD = "INSTANCE_STATE_PENDING_CARD_PASSWORD";
    private static final String INSTANCE_STATE_PENDING_USE_EXISTING_SESSION_IF_POSSIBLE = "INSTANCE_STATE_PENDING_USE_EXISTING_SESSION_IF_POSSIBLE";
    private static final String INSTANCE_STATE_PENDING_DELETE_KEY_PUBLIC_KEY_BYTES = "INSTANCE_STATE_PENDING_DELETE_KEY_PUBLIC_KEY_BYTES";
    private static final String INSTANCE_STATE_PENDING_BACKUP_CARD = "INSTANCE_STATE_PENDING_BACKUP_CARD";
    private static final String INSTANCE_STATE_PENDING_SAVE_KEYS_TO_CARD = "INSTANCE_STATE_PENDING_SAVE_KEYS_TO_CARD";
    private static final String INSTANCE_STATE_PENDING_GENERATE_SEED = "INSTANCE_STATE_PENDING_GENERATE_SEED";
    private static final String INSTANCE_STATE_PENDING_SETUP_CARD = "INSTANCE_STATE_PENDING_SETUP_CARD";
    private static final String INSTANCE_STATE_PENDING_GET_DATA = "INSTANCE_STATE_PENDING_GET_DATA";
    private static final String INSTANCE_STATE_PENDING_WIPE = "INSTANCE_STATE_PENDING_WIPE";

    private static SecureElementAppletImpl _cachedSecureElementApplet;

    private static String ARG_SHOW_GETTING_STARTED = "show_getting_started";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (this instanceof de.schildbach.wallet.ui.WalletActivity && IntegrationConnector.getWallet(this) == null ) {
            Intent intentToStartTapToBeginActivity = new Intent(this, MainActivity.class);
            intentToStartTapToBeginActivity.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intentToStartTapToBeginActivity);
            this.finish();
            return;
        }

        _pendingIntent = PendingIntent.getActivity(
                this, 0, new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);

        _nfcAdapter = NfcAdapter.getDefaultAdapter(this);
        // if (mNfcAdapter == null) {
        //     This will never happen because we're requiring in the manifest that the device is NFC capable.
        // }


        // The card will have two NDEF records: a URL and an Android Application Record
        // Enable foreground dispatch on the URL to make sure this current activity isn't replaced by the wallet activity (since
        // that's the only activity with the URL statically declared in the manifest)
        IntentFilter ndefFilter = new IntentFilter(NfcAdapter.ACTION_NDEF_DISCOVERED);
        ndefFilter.addDataScheme("https");
        ndefFilter.addDataAuthority("www.helioscard.com", null);
        ndefFilter.addDataPath("/tag.html", PatternMatcher.PATTERN_LITERAL);

        _intentFiltersArray = new IntentFilter[] {ndefFilter};

        if (this instanceof de.schildbach.wallet.ui.WalletActivity) {
            showGetStartedDialogIfNeeded();
        }

        Intent intent = getIntent();
        if (this instanceof MainActivity && intent.getBooleanExtra(ARG_SHOW_GETTING_STARTED, false)) {
            showGetStartedDialogIfNeeded();
        }

        // if we're first launched by an NFC tag, we don't get an onNewIntent message,
        // so route it through now
        boolean startedByCardTap = processIntent(intent);

        if ( WalletGlobals.getInstance(this).getCardIdentifier() == null && !(this instanceof MainActivity) && !(this instanceof InitializeCardActivity)) {
            // This app has never been used with a card before
            if (startedByCardTap) {
                // But we were started by an intent which represented a card tap - everything has been handled, nothing for us to
                // do here
                _logger.info("onCreate: started by NFC tap, bailing");
                EULAAndSafetyDialogFragment.promptIfNeeded(getFragmentManager(), this);
                return;
            }

            // Otherwise, ensure we are focused on the tap to begin screen to prompt the user to tap
            Intent intentToStartTapToBeginActivity = new Intent(this, MainActivity.class);
            intentToStartTapToBeginActivity.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(intentToStartTapToBeginActivity);
            this.finish();
            return;
        }
        EULAAndSafetyDialogFragment.promptIfNeeded(getFragmentManager(), this);
    }


    @Override
    protected void onSaveInstanceState(Bundle outState) {
        _logger.info("onSaveInstanceState: called");
        super.onSaveInstanceState(outState);

        outState.putString(INSTANCE_STATE_PENDING_CARD_PASSWORD, _pendingCardPassword);
        outState.putBoolean(INSTANCE_STATE_PENDING_USE_EXISTING_SESSION_IF_POSSIBLE, _pendingUseExistingSessionIfPossible);
        outState.putByteArray(INSTANCE_STATE_PENDING_DELETE_KEY_PUBLIC_KEY_BYTES, _pendingDeleteKeyPublicKeyBytes);
        outState.putBoolean(INSTANCE_STATE_PENDING_BACKUP_CARD, _pendingBackupCard);
        outState.putBoolean(INSTANCE_STATE_PENDING_SAVE_KEYS_TO_CARD, _pendingSaveKeysToCard);
        outState.putBoolean(INSTANCE_STATE_PENDING_GENERATE_SEED, _pendingGenerateSeed);
        outState.putBoolean(INSTANCE_STATE_PENDING_SETUP_CARD, _pendingSetupCard);
        outState.putBoolean(INSTANCE_STATE_PENDING_GET_DATA, _pendingGetData);
        outState.putBoolean(INSTANCE_STATE_PENDING_WIPE, _pendingWipe);
    }

    @Override
    protected void onRestoreInstanceState(Bundle savedInstanceState) {
        _logger.info("onRestoreInstanceState: called");
        super.onRestoreInstanceState(savedInstanceState);

        _pendingCardPassword = savedInstanceState.getString(INSTANCE_STATE_PENDING_CARD_PASSWORD);
        _pendingUseExistingSessionIfPossible = savedInstanceState.getBoolean(INSTANCE_STATE_PENDING_USE_EXISTING_SESSION_IF_POSSIBLE, false);
        _pendingDeleteKeyPublicKeyBytes = savedInstanceState.getByteArray(INSTANCE_STATE_PENDING_DELETE_KEY_PUBLIC_KEY_BYTES);
        _pendingBackupCard = savedInstanceState.getBoolean(INSTANCE_STATE_PENDING_BACKUP_CARD);
        _pendingSaveKeysToCard = savedInstanceState.getBoolean(INSTANCE_STATE_PENDING_SAVE_KEYS_TO_CARD);
        _pendingGenerateSeed = savedInstanceState.getBoolean(INSTANCE_STATE_PENDING_GENERATE_SEED);
        _pendingSetupCard = savedInstanceState.getBoolean(INSTANCE_STATE_PENDING_SETUP_CARD);
        _pendingGetData = savedInstanceState.getBoolean(INSTANCE_STATE_PENDING_GET_DATA);
        _pendingWipe = savedInstanceState.getBoolean(INSTANCE_STATE_PENDING_WIPE);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }

    @Override
    protected void onResume() {
        super.onResume();
        _nfcAdapter.enableForegroundDispatch(this, _pendingIntent, _intentFiltersArray, null);
    }

    @Override
    protected void onPause() {
        super.onPause();
        _nfcAdapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        _logger.error("onNewIntent: called");
        processIntent(intent);
    }

    public boolean processIntent(Intent intent) {
        _logger.info("processIntent: called");
        if (doesIntentComeFromHeliosCard(intent)) {
            // clear out any cached secure element that we have
            _cachedSecureElementApplet = null;

            try {
                Tag tagFromIntent = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
                // isoDep should be non-null, this is the only technology type we're listening for
                SmartCardReader smartCardReader = new SmartCardReaderImpl(tagFromIntent);
                if (!smartCardReader.checkConnection()) {
                    _logger.info("processIntent: bailing, reader not connected");
                    return true;
                }
                _cachedSecureElementApplet = new SecureElementAppletImpl(smartCardReader);

                FragmentManager fragmentManager = getFragmentManager();
                String currentCardIdentifier = WalletGlobals.getInstance(this).getCardIdentifier();
                String newCardIdentifier = _cachedSecureElementApplet.getCardIdentifier();
//                PromptToSaveBackupDataDialogFragment promptToSaveBackupDataDialogFragment = (PromptToSaveBackupDataDialogFragment)fragmentManager.findFragmentByTag(PromptToSaveBackupDataDialogFragment.TAG);

//                if (_pendingBackupCard) {
//                    _logger.info("processIntent: pendingBackupCard was true");
//                    // Special case - we're in the middle of a backup/restore
//                    if (_cachedSecureElementApplet.getPINState() == SecureElementApplet.PINState.NOT_SET) {
//                        // this card has never been initialized - toast the user and bail
//                        Toast.makeText(this, getResources().getString(R.string.nfc_aware_activity_card_not_initialized), Toast.LENGTH_LONG).show();
//                        return true;
//                    }
//                } else if (promptToSaveBackupDataDialogFragment != null && !_pendingSaveKeysToCard) {
//                    _logger.info("processIntent: promptToSaveBackupDataDialogFragment existed");
//                    // the user is being prompted to tap in order to save keys to a card
//                    String sourceCardIdentifier = promptToSaveBackupDataDialogFragment.getSourceCardIdentifier();
//                    if (sourceCardIdentifier != null && sourceCardIdentifier.equals(newCardIdentifier)) {
//                        _logger.info("processIntent: user tapped same card during restore");
//                        // the user tapped the same card that the backup data came from - tell the user to tap a different card
//                        Toast.makeText(this, getResources().getString(R.string.nfc_aware_activity_same_card_tapped), Toast.LENGTH_LONG).show();
//                        return true;
//                    }
//
//                    // There are two possibilities: this card has never had a PIN set, or it has a PIN/blank PIN
//                    // 1. It's never had a PIN set
//                    // 2. We have to login to the card to get the authenticated session.
//                    if (!_cachedSecureElementApplet.isAuthenticated()) {
//                        SecureElementApplet.PINState pinState = _cachedSecureElementApplet.getPINState();
//                        if (pinState == SecureElementApplet.PINState.NOT_SET) {
//                            // The new card has never been used.  If we are restoring from an existing card, make its password the same as the card we are backing up from.
//                            _logger.info("processIntent: card never used, setting password");
//                            String password = promptToSaveBackupDataDialogFragment.getPassword();
//                            if (password != null) {
//                                PleaseWaitDialogFragment pleaseWaitDialogFragment = PleaseWaitDialogFragment.show(getFragmentManager());
//                                (new SetPasswordOnCardAsyncTask(_cachedSecureElementApplet, pleaseWaitDialogFragment, SetPasswordOnCardAsyncTaskType.DOING_RESTORE, null, password)).execute();
//                                return true;
//                            } else {
//                                // show an error indicating this card has no password set
//                                Toast.makeText(this, getResources().getString(R.string.nfc_aware_activity_error_no_password_set_on_card), Toast.LENGTH_LONG).show();
//                                return true;
//                            }
//                        } else {
//                            // The PIN on this new card is already set.  Prompt the user to login
//                            _logger.info("processIntent: logging on now");
//                            _pendingSaveKeysToCard = true;
//                            getSecureElementAppletPromptIfNeeded(true, false);
//                            return true;
//                        }
//                    }
//
//                    return true;
//                }

                if (!_pendingBackupCard && !_pendingSaveKeysToCard) {
                    _logger.info("processIntent: normal tap");

                    if (handleNormalTap(_cachedSecureElementApplet, currentCardIdentifier, newCardIdentifier)) {
                        // handleNormalTap wants us to bail out of this method (it probably restarted the app due to a key sync operation)
                        return true;
                    }
                    // else otherwise fall through
                }

                PromptForPasswordDialogFragment promptForPasswordDialogFragment = (PromptForPasswordDialogFragment)fragmentManager.findFragmentByTag(PromptForPasswordDialogFragment.TAG);
                if (promptForPasswordDialogFragment != null) {
                    // we're currently prompting the user to enter the password
                    // update the dialog to have the number of password attempts left
                    promptForPasswordDialogFragment.generatePasswordAttemptsLeftText();
                    return true;
                }

                boolean tapRequested = false;
                PromptForTapDialogFragment promptForTapDialogFragment = (PromptForTapDialogFragment)fragmentManager.findFragmentByTag(PromptForTapDialogFragment.TAG);
                if (promptForTapDialogFragment != null) {
                    promptForTapDialogFragment.dismiss();
                    tapRequested = true;

                    if (_pendingCardPassword != null) {
                        // we requested the user to tap the card so that we could log the user in
                        // let the loginToCard function take care of logging in and then notifying the
                        // subclass that there's a smart card session
                        loginToCard(_pendingCardPassword);
                        return true;
                    }
                }

                if(!_cachedSecureElementApplet.isSeedSet() && !tapRequested) {
                    showGetStartedDialogIfNeeded();
                    return true;
                }

//todo: don't want to prompt for the password each time the card is tapped, only if we need to
//figure out the right location to put this

//                if (!_cachedSecureElementApplet.isAuthenticated() && !tapRequested) {
//                    // The PIN is set, but the user is not logged in, authentication needed for getting data, prompt the user to login
//                    _logger.info("processIntent (getdata): logging on now");
//                    _pendingGetData = true;
//                    getSecureElementAppletPromptIfNeeded(true, false);
//                    return true;
//                } else {
//                    try {
//                        _cachedSecureElementApplet.getAllData();
//                    } catch (IOException e) {
//                        showException(e);
//                        _cachedSecureElementApplet = null;
//                        _logger.error("onNewIntent: IOException while getting data: " + e.toString());
//                    }
//                }

                // let the activity know a card has been detected
                handleCardDetectedSuper(_cachedSecureElementApplet, tapRequested, false, null, null);

                // the wallet may have a key now - hide the get started dialog if it's showing
//                hideGetStartedDialogIfNeeded();
                return true;

            } catch(IOException e) {
                showException(e);
                _cachedSecureElementApplet = null;
                _logger.error("onNewIntent: IOException getting cached secure element: " + e.toString());
            }
        }

        return false;
    }

    private boolean handleNormalTap(SecureElementApplet secureElementApplet, String currentCardIdentifier, String newCardIdentifier) throws IOException {
        _logger.info("handleNormalTap: called");

        // set the card identifier appropriately in the bitcoin wallet
        WalletGlobals walletGlobals = WalletGlobals.getInstance(this);

        // Synchronize the keys with the secure element.  E.g. make sure our local cache of public keys matches
        // what's on this card
        // TODO: there's a race condition here, where the wallet has the newly synchronized keys, but it could be the case we had to
        // tell the service to stop and destroy its current block chain file.  But there's a chance the process could be terminated
        // or the device could be rebooted before the service gets a chance to do that

        boolean needsToGoToInitializationScreen = false;
        boolean cardIdentifierWasChanged = false;

        FragmentManager fragmentManager = getFragmentManager();
        PromptOnNewCardDialogFragment promptOnNewCardDialogFragment = (PromptOnNewCardDialogFragment)fragmentManager.findFragmentByTag(PromptOnNewCardDialogFragment.TAG);
        if (currentCardIdentifier != null && !currentCardIdentifier.equals(newCardIdentifier)) {
            _logger.info("handleNormalTap: had an old card identifier, but new card was tapped");
            // we are switching cards - prompt the user
            if (promptOnNewCardDialogFragment != null) {
                _logger.info("handleNormalTap: already showing new card dialog fragment");
                // we were already showing the prompt on new card dialog fragment
                String cardBeingPromptedToSwitchToIdentifier = promptOnNewCardDialogFragment.getCardBeingPromptedToSwitchToIdentifier();
                promptOnNewCardDialogFragment.dismiss();
                if (cardBeingPromptedToSwitchToIdentifier.equals(newCardIdentifier)) {
                    // the user tapped the card we were prompting him to switch to
                    _logger.info("handleNormalTap: switching to card that was being prompted to switch to");
                    walletGlobals.setCardIdentifier(this, newCardIdentifier);
                    cardIdentifierWasChanged = true;
                } else {
                    _logger.info("handleNormalTap: user tapped 3rd card while being prompted to switch to 2nd");
//                    PromptOnNewCardDialogFragment.prompt(fragmentManager, PromptOnNewCardDialogFragment.TYPE_NEW_CARD, currentCardIdentifier, newCardIdentifier);
                    return true;
                }
            } else {
                _logger.info("handleNormalTap: prompting user to switch cards");
                // prompt the user to switch cards
                PromptOnNewCardDialogFragment.prompt(fragmentManager, PromptOnNewCardDialogFragment.TYPE_NEW_CARD, currentCardIdentifier, newCardIdentifier );
                return true;
            }
        } else if (promptOnNewCardDialogFragment != null) {
            // we were showing the prompt on new card dialog fragment, but the user tapped the old card
            // dismiss the dialog
            _logger.info("handleNormalTap: same card tapped while showing new card dialog, dismissing");
            promptOnNewCardDialogFragment.dismiss();
        } else if (currentCardIdentifier == null){
            // a card was tapped, and none was registered before
            _logger.info("handleNormalTap: new card tapped and no registered old card");
            walletGlobals.setCardIdentifier(this, newCardIdentifier);
        }

        if (secureElementApplet.getPINState() == SecureElementApplet.PINState.NOT_SET) {
            // this is a brand new card.  we are going to need to send the user to the initialization screen
            _logger.info("handleNormalTap: detected uninitialized card");
            // clear out the card we're tracking
            walletGlobals.setCardIdentifier(this, null);
//todo: either we need to re-name InitializeCardActivity to SetPasswordActivity, or we need to move
//the logic of card setup (seed, slots) into that activity too
            if (this instanceof InitializeCardActivity) {
                _logger.info("handleNormalTap: already in InitializeCardActivity, not doing anything");
            } else {
                _logger.info("handleNormalTap: need to go to initialization screen");
                needsToGoToInitializationScreen = true;
            }
        }

//todo: we need to handle the case where the wallet is tracking a card, but the card is wiped
//in this case the card id is still the same but the seed is not set

//        PromptForTapOnceMoreDialogFragment promptForTapOnceMoreDialogFragment = (PromptForTapOnceMoreDialogFragment)fragmentManager.findFragmentByTag(PromptForTapOnceMoreDialogFragment.TAG);
//        Wallet wallet = IntegrationConnector.getWallet(this);
//        boolean serviceNeedsToClearAndRestart = walletGlobals.synchronizeKeys(this, wallet, ecPublicKeyEntries, promptForTapOnceMoreDialogFragment == null);
//        if (serviceNeedsToClearAndRestart) {
//            // the keys between the secure element and our cached copy of public keys didn't match
//            _logger.info("handleNormalTap: service needs to clear and restart");
//        }
//
//        if (serviceNeedsToClearAndRestart) {
//            if (promptForTapOnceMoreDialogFragment == null) {
//                // We were tapped by a card but we weren't tracking all the keys - restart the service
//                // Also, there was no tap to finish dialog showing, or there was one, but the user tapped a different card
//                IntegrationConnector.deleteBlockchainAndRestartService(this);
//            } else {
//                _logger.info("handleNormalTap: ignoring service needs to restart due to prompt for tap dialog");
//                serviceNeedsToClearAndRestart = false;
//            }
//        }

        if (cardIdentifierWasChanged /*|| serviceNeedsToClearAndRestart */|| needsToGoToInitializationScreen) {
            // We need to restart the application because we have a new card, or we have new keys, or we need to go to the initialization screen
            // We want to clear any activities off the task and basically restart the activity stack focused on a new card
            Intent intentToRelaunchApplication = new Intent(this, needsToGoToInitializationScreen ? InitializeCardActivity.class : IntegrationConnector.WALLET_ACTIVITY_CLASS);
            intentToRelaunchApplication.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intentToRelaunchApplication);
            this.finish();

            return true;
        }

//        if (promptForTapOnceMoreDialogFragment != null) {
//            // We were showing a tap to finish dialog - where we were asking the user to tap so we could
//            // synchronize the keys.  That has already been done by the time we get here, so nothing to do here.
//            promptForTapOnceMoreDialogFragment.dismiss();
//            // it's possible we generated a key - dismiss the get started dialog if appropriate
//            hideGetStartedDialogIfNeeded();
//            return true;
//        }

        return false;
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {

        super.onCreateOptionsMenu(menu);

        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.helioscard, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(final MenuItem item)
    {
        switch (item.getItemId())
        {
            case R.id.wipe_card:

                // Need a connection to the card to wipe
                SecureElementApplet secureElementApplet = this.getSecureElementAppletPromptIfNeeded(false, true);
                if (secureElementApplet == null) {
                    // the user wasn't holding the card to the phone, but now the user is being prompted to tap the card,
                    // finish this operation later
                    _pendingWipe = true;
                    return true;
                }
                wipeCardPostTap(secureElementApplet);
                return true;

            case R.id.clear_anti_malware_key:
                clearAntiMalwareKey();
                break;

            case R.id.change_password:
                promptToChangePassword();
                return true;

            case R.id.check_card:
                setupCardPrePreTap();
                return true;

        }

        return super.onOptionsItemSelected(item);
    }

    protected boolean doesIntentComeFromHeliosCard(Intent intent) {
        if (intent == null) {
            return false;
        }

        // the Helios card should have an Android Application record in it corresponding to this package
        String action = intent.getAction();
        if (action == null || !action.equals(NfcAdapter.ACTION_NDEF_DISCOVERED)) {
            return false;
        }

        Parcelable[] rawMsgs = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
        if (rawMsgs == null || rawMsgs.length == 0) {
            return false;
        }

        for (int i = 0; i < rawMsgs.length; i++) {
            // only one message sent during the beam
            NdefMessage msg = (NdefMessage) rawMsgs[i];
            // record 0 contains the MIME type, record 1 is the AAR, if present
            NdefRecord[] ndefRecords = msg.getRecords();
            _logger.error("doesIntentComeFromHeliosCard: found " + ndefRecords.length + " NDEF records");
            for (int j = 0; j < ndefRecords.length; j++) {
                String payload = new String(ndefRecords[j].getPayload());
                _logger.error("doesIntentComeFromHeliosCard: found payload of" + payload);
                if (ndefRecords[j].getTnf() == NdefRecord.TNF_EXTERNAL_TYPE && payload.startsWith("com.helioscard.wallet")) {
                    _logger.error("doesIntentComeFromHeliosCard: found matching AAR record");
                    return true;
                }
            }
        }

        return false;
    }

    protected boolean checkIfNFCRadioOnPromptUser(boolean messageStatesNFCIsRequired) {
        if (!_nfcAdapter.isEnabled()) {
            // the NFC radio is off
            // prompt the user to turn it on

            AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(this);

            // set title
            alertDialogBuilder.setTitle(getResources().getString(R.string.nfc_aware_activity_enable_nfc_dialog_title));

            String alertDialogMessage = getResources().getString(messageStatesNFCIsRequired ? R.string.nfc_aware_activity_enable_nfc_dialog_message : R.string.nfc_aware_activity_enable_nfc_dialog_some_operations_will_not_work);
            // set dialog message
            alertDialogBuilder
                    .setMessage(alertDialogMessage)
                    .setCancelable(false)
                    .setPositiveButton(getResources().getString(R.string.helioscard_ok), new DialogInterface.OnClickListener() {
                        @SuppressLint("InlinedApi")
                        public void onClick(DialogInterface dialog, int id) {
                            // TODO: restore below code
                            // if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN) {
                            // Settings.ACTION_NFC_SETTINGS is only available in API level 16+
                            // startActivity(new Intent(Settings.ACTION_NFC_SETTINGS));
                            // } else {
                            // put the user in the wireless settings menu
                            startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS));
                            // }
                        }
                    })
                    .setNegativeButton(getResources().getString(R.string.helioscard_cancel), new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int id) {
                            // if this button is clicked, just close
                            // the dialog box and do nothing
                            dialog.cancel();
                        }
                    });

            alertDialogBuilder.show();
            return false;
        }

        return true;
    }


    public SecureElementApplet getSecureElementAppletPromptIfNeeded(boolean requirePassword, boolean useExistingSessionIfPossible) {
        if (!checkIfNFCRadioOnPromptUser(true)) {
            // the NFC radio isn't on, the user is being prompted to turn it on
            return null;
        }

        _pendingUseExistingSessionIfPossible = useExistingSessionIfPossible;

        try {
            if (_cachedSecureElementApplet != null && _cachedSecureElementApplet.checkConnection()) {
                if (requirePassword && (!_cachedSecureElementApplet.isAuthenticated() || !_pendingUseExistingSessionIfPossible)) {
                    // the caller is asking us for an authenticated session but we don't have one, or we do have an authenticated session
                    // but the caller wants to force an authentication anyway
                    showPromptForPasswordDialog();
                    return null;
                }
                // we have a connection to the SecureElementApplet - return the connection
                return _cachedSecureElementApplet;
            } else {
                _cachedSecureElementApplet = null;
                if (requirePassword) {
                    showPromptForPasswordDialog();
                } else {
                    showPromptForTapDialog(PromptForTapDialogFragment.TYPE_NORMAL);
                }
                return _cachedSecureElementApplet;
            }
        } catch(IOException e) {
            _cachedSecureElementApplet = null;
            return _cachedSecureElementApplet;
        }
    }

    private void showPromptForPasswordDialog() {
        int type = PromptForPasswordDialogFragment.TYPE_NORMAL;
//        if (_pendingBackupCard) {
//            type = PromptForPasswordDialogFragment.TYPE_BACKUP;
//        } else if (_pendingSaveKeysToCard) {
//            type = PromptForPasswordDialogFragment.TYPE_SAVE_KEYS_TO_CARD;
//        }
        PromptForPasswordDialogFragment.prompt(getFragmentManager(), type);
    }

    // if type = true - just prompts the user to tap
    // if type = false - prompts the user to tap to finish signing, connection was lost
    public void showPromptForTapDialog(int type) {
//        if (_pendingBackupCard) {
//            type = PromptForTapDialogFragment.TYPE_BACKUP;
//        } else if (_pendingSaveKeysToCard) {
//            type = PromptForTapDialogFragment.TYPE_SAVE_KEYS_TO_CARD;
//        }
        PromptForTapDialogFragment.prompt(getFragmentManager(), type);
    }

    public void userProceededOnPasswordDialog(String password) {
        _logger.info("userProceededOnPasswordDialog: called");
        loginToCard(password);
    }

    private void loginToCard(String password) {
        _logger.info("loginToCard: called");
        // get a secure element session (prompt the user to tap if needed
        SecureElementApplet secureElementApplet = getSecureElementAppletPromptIfNeeded(false, true);
        if (secureElementApplet == null) {
            // the user is being prompted to tap - just cache the password to try later
            _logger.info("loginToCard: waiting for session");
            _pendingCardPassword = password;
            return;
        }

        try {
            if (secureElementApplet.isAuthenticated()
                    && (_pendingUseExistingSessionIfPossible || secureElementApplet.getPINState() == SecureElementApplet.PINState.BLANK)) {
                // if the secure element is already authenticated
                // and either it's ok to re-use the authenticated session, or the reason we're authenticated is because the PIN is blank
                // then we're good to go
                _logger.info("loginToCard: card already authenticated");

                handleCardDetectedSuper(secureElementApplet, true, true, null, password);
                return;
            }

            PleaseWaitDialogFragment pleaseWaitDialogFragment = PleaseWaitDialogFragment.show(getFragmentManager());
            (new LoginToCardAsyncTask(secureElementApplet, pleaseWaitDialogFragment, password)).execute();

        } catch (IOException e) {
            _logger.info("loginToCard: IOException e while logging into card: " + e.toString());
            showException(e);
            _cachedSecureElementApplet = null;
        } finally {
            _pendingCardPassword = null;
        }
    }

    private class LoginToCardAsyncTask extends AsyncTask<Void, Void, IOException> {
        private SecureElementApplet _secureElementApplet;
        private PleaseWaitDialogFragment _pleaseWaitDialogFragment;
        private String _password;
        private volatile byte[] _hashedPasswordBytes;
        public LoginToCardAsyncTask(SecureElementApplet secureElementApplet, PleaseWaitDialogFragment pleaseWaitDialogFragment, String password) {
            _secureElementApplet = secureElementApplet;
            _pleaseWaitDialogFragment = pleaseWaitDialogFragment;
            _password = password;
        }

        @Override
        protected IOException doInBackground(Void... params) {
            try {
                _hashedPasswordBytes = _secureElementApplet.login(_password, null);
            } catch (IOException e) {
                return e;
            }
            return null;
        }

        @Override
        protected void onPostExecute(IOException e) {
            _pleaseWaitDialogFragment.dismiss();
            try {
                if (e == null) {
                    _logger.info("loginToCard: successful");
                    // logged in successfully
                    handleCardDetectedSuper(_secureElementApplet, true, true, _hashedPasswordBytes, _password);
                } else if (e instanceof IOException) {
                    // error while logging in (possibly wrong password)
                    _logger.info("loginToCard: failed to login");

                    // draw some UI for the user to indicate the error
                    showException(e);

                    // let the user try logging in again
                    showPromptForPasswordDialog();
                    return;
                }
            } finally {
                _password = null;
                _hashedPasswordBytes = null;
            }
        }

    }


    public SecureElementApplet getCachedSecureElementApplet() {
        // assume that if someone is explicitly asking us for the cached secure element, they
        // want to have a connection to it.  If we're not actually able to connect, clear the cache.
        if (_cachedSecureElementApplet != null) {
            if (!_cachedSecureElementApplet.checkConnection()) {
                _logger.info("getCachedSecureElementApplet: clearing cache since not connected");
                _cachedSecureElementApplet = null;
            }
        }
        return _cachedSecureElementApplet;
    }

    protected void resetState() {
        _pendingCardPassword = null;
        _pendingDeleteKeyPublicKeyBytes = null;
        _pendingChangePasswordNewPassword = null;
        _pendingBackupCard = false;
        _pendingSaveKeysToCard = false;
        _pendingGenerateSeed = false;

        // we have no keys in the wallet - prompt the user to add one
        hideGetStartedDialogIfNeeded();

        userCanceledSecureElementPrompt();
    }

    protected void userCanceledSecureElementPrompt() {
        // subclasses can override this if they want to hear about this event
    }

    protected void promptToChangePassword() {
        if (!checkIfNFCRadioOnPromptUser(true)) {
            // the NFC radio isn't on, prompt the user to turn it on and abort
            return;
        }

        HeliosChangePasswordDialogFragment.prompt(getFragmentManager());
    }

    public void changePasswordPreTap(String newPassword) {
        _logger.info("changePasswordPreTap: called");
        // get a secure element session that is authenticated (authenticated session needed to add a key)
        // Note that we do NOT use the existing session - we want to force the user to enter the password
        // because we need the old password in the change password command
        this.getSecureElementAppletPromptIfNeeded(true, false);
        _pendingChangePasswordNewPassword = newPassword;
    }

    protected void changePasswordPostTap(SecureElementApplet secureElementApplet, SetPasswordOnCardAsyncTaskType type, String oldPassword, String newPassword) {
        _logger.info("changePasswordPostTap: called");
        PleaseWaitDialogFragment pleaseWaitDialogFragment = PleaseWaitDialogFragment.show(getFragmentManager());
        (new SetPasswordOnCardAsyncTask(secureElementApplet, pleaseWaitDialogFragment, type, oldPassword, newPassword)).execute();
    }

    protected void wipeCardPostTap(SecureElementApplet secureElementApplet) {
        _logger.info("wipeCardPostTap: called");
        PleaseWaitDialogFragment pleaseWaitDialogFragment = PleaseWaitDialogFragment.show(getFragmentManager());
        (new WipeCardAsyncTask(secureElementApplet, pleaseWaitDialogFragment)).execute();
    }

    private class SetPasswordOnCardAsyncTask extends AsyncTask<Void, Void, IOException> {


        private SecureElementApplet _secureElementApplet;
        private PleaseWaitDialogFragment _pleaseWaitDialogFragment;
        private SetPasswordOnCardAsyncTaskType _type;;
        private String _oldPassword;
        private String _newPassword;

        public SetPasswordOnCardAsyncTask(SecureElementApplet secureElementApplet, PleaseWaitDialogFragment pleaseWaitDialogFragment, SetPasswordOnCardAsyncTaskType type, String oldPassword, String newPassword) {
            _secureElementApplet = secureElementApplet;
            _pleaseWaitDialogFragment = pleaseWaitDialogFragment;
            _type = type;
            _oldPassword = oldPassword;
            _newPassword = newPassword;
        }

        @Override
        protected IOException doInBackground(Void... params) {
            try {
                _secureElementApplet.setCardPassword(_oldPassword, _newPassword);
                if (_type == SetPasswordOnCardAsyncTaskType.DOING_RESTORE) {
                    _secureElementApplet.login(_newPassword, null);
                }
            } catch (IOException e) {
                return e;
            }
            return null;
        }

        @Override
        protected void onPostExecute(IOException e) {
            _pleaseWaitDialogFragment.dismiss();
            try {
                if (e == null) {
                    _logger.info("changePasswordAsyncTask: successful");
                    if (_type == SetPasswordOnCardAsyncTaskType.NORMAL) {
                        // if we got here it worked.  Tell the user the password was changed successfully
                        Toast.makeText(NFCAwareActivity.this, getResources().getString(R.string.nfc_aware_activity_password_successfully_changed), Toast.LENGTH_LONG).show();
                    } else if (_type == SetPasswordOnCardAsyncTaskType.DOING_RESTORE){
//                        saveKeysToCardPostTap(_secureElementApplet);
                    } else if (_type == SetPasswordOnCardAsyncTaskType.DOING_INITIALIZATION) {
                        _logger.info("changePasswordAsyncTask: card initialized");
                        // now that we have initialized this card, save the card identifier as our most recently used card

                        try {

                            WalletGlobals.getInstance(NFCAwareActivity.this).setCardIdentifier(NFCAwareActivity.this, _secureElementApplet.getCardIdentifier());

                            // We want to now send the user to the tap to begin screen with the GettingStartedDialog/SetupKeys dialog shown
                            // Since the intent won't have been started as a result of a tap we need to give the activity a little hint
                            // about what we want it to do which is why we pass in the ARG_SHOW_GETTING_STARTED flag

                            Intent intentToStartTapToBeginActivity = new Intent(NFCAwareActivity.this, MainActivity.class);
                            intentToStartTapToBeginActivity.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                            intentToStartTapToBeginActivity.putExtra(ARG_SHOW_GETTING_STARTED, true);
                            startActivity(intentToStartTapToBeginActivity);

                            NFCAwareActivity.this.finish();

                        } catch (IOException error) {
                            e = error;
                            _logger.info("changePasswordAsyncTask: IO exception setting card identifier: " + e.toString());
                        }
                    }
                }
                if (e instanceof IOException) {
                    // error while logging in (possibly wrong password)
                    _logger.info("changePasswordAsyncTask: failed to change password");

                    // draw some UI for the user to indicate the error
                    showException(e);

                    return;
                }
            } finally {
                _oldPassword = null;
                _newPassword = null;
            }
        }

    }


    protected void handleCardDetectedSuper(SecureElementApplet secureElementApplet, boolean tapRequested, boolean authenticated, byte[] hashedPasswordBytes, String password) {

        _logger.info("handleCardDetectedSuper");

        if (_pendingDeleteKeyPublicKeyBytes != null) {
            byte[] pendingDeleteKeyPublicKeyBytes = _pendingDeleteKeyPublicKeyBytes;
            _pendingDeleteKeyPublicKeyBytes = null;
//            deleteKeyPostTap(secureElementApplet, pendingDeleteKeyPublicKeyBytes);
            return;
        } else if (_pendingChangePasswordNewPassword != null) {
            String newPassword = _pendingChangePasswordNewPassword;
            _pendingChangePasswordNewPassword = null;
            changePasswordPostTap(secureElementApplet, SetPasswordOnCardAsyncTaskType.NORMAL, password, newPassword);
            return;
        } else if (_pendingBackupCard) {
            _pendingBackupCard = false;
//            backupCardPostTap(secureElementApplet, password);
            return;
        } else if (_pendingWipe) {
            _pendingWipe = false;
            wipeCardPostTap(secureElementApplet);
            return;
        } else if (_pendingSaveKeysToCard) {
            _pendingSaveKeysToCard = false;
//            saveKeysToCardPostTap(secureElementApplet);
            return;

//todo:remove as this is now done in _pendingCardSetup
        } else if (_pendingGenerateSeed) {

            _pendingGenerateSeed = false;
            try {
                _cachedSecureElementApplet.generateSeed();
            } catch (IOException e) {
                showException(e);
                _cachedSecureElementApplet = null;
                _logger.error("handleCardDetectedSuper: IOException while generating seed: " + e.toString());
            }

        } else if (_pendingSetupCard) {

            _pendingSetupCard = false;

            // We should now be authenticated
            if (authenticated) {
                setupCardPrePostTap(secureElementApplet, password);
            } else {
                _logger.error("handleCardDetectedSuper: not authenticated for card setup command");
            }

        } else if (_pendingGetData) {

            _pendingGetData = false;

            // We should now be authenticated
            if (authenticated) {

                PleaseWaitDialogFragment pleaseWaitDialogFragment = PleaseWaitDialogFragment.show(getFragmentManager());
                (new CheckKeysAsyncTask(_cachedSecureElementApplet, pleaseWaitDialogFragment, password)).execute();

            } else {
                _logger.error("handleCardDetectedSuper: not authenticated for pending get data command");
            }
        }

        handleCardDetected(secureElementApplet, tapRequested, authenticated, hashedPasswordBytes);
    }

    protected void handleCardDetected(SecureElementApplet secureElementApplet, boolean tapRequested, boolean authenticated, byte[] hashedPasswordBytes) {
        // default implementation does nothing, override to hear about card detection events
    }

    // utility method for subclasses to show errors
    public void showException(IOException e) {
        String errorMessage;

        if (e instanceof WrongPasswordException) {
            // Toast.makeText(this, this.getResources().getString("Wrong password"), Toast.LENGTH_LONG).show();
            errorMessage = getResources().getString(R.string.nfc_aware_activity_error_dialog_message_wrong_password);
        } else if (e instanceof SmartCardFullException) {
            errorMessage = getResources().getString(R.string.nfc_aware_activity_error_dialog_message_smartcard_full);
        } else if (e instanceof KeyAlreadyExistsException) {
            errorMessage = getResources().getString(R.string.nfc_aware_activity_error_dialog_message_key_already_exists);
        } else if (e instanceof TagLostException) {
            errorMessage = getResources().getString(R.string.nfc_aware_activity_error_dialog_message_tag_lost);
        } else if (e instanceof CardWasWipedException) {
            _logger.info("showException: card was wiped");
            // the card was just wiped - clear the current card identifier, reset the block chain, and restart the app
//            WalletGlobals walletGlobals = WalletGlobals.getInstance(this);
//            walletGlobals.setCardIdentifier(this, null);
//            Wallet wallet = IntegrationConnector.getWallet(this);
//            List<ECKey> listFromCachedWallet = wallet.getKeys();
//            if (listFromCachedWallet.size() > 0) {
//                // persist the fact that we're about to modify the wallet, in case we can interrupted
//                // before we get a chance to tell the service to delete the block chain and restart
//                walletGlobals.persistServiceNeedsToReplayBlockchain(this);
//
//                // Remove all the keys from the wallet
//                for (int i = 0; i < listFromCachedWallet.size(); i++) {
//                    ECKey keyFromCachedWallet = listFromCachedWallet.get(i);
//                    wallet.removeKey(keyFromCachedWallet);
//                }
//
//                // Replay the block chain
//                IntegrationConnector.deleteBlockchainAndRestartService(this);
//            }
//
//            Intent intentToRestartApplication = new Intent(this, IntegrationConnector.WALLET_ACTIVITY_CLASS);
//            intentToRestartApplication.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
//            startActivity(intentToRestartApplication);
            errorMessage = getResources().getString(R.string.nfc_aware_activity_error_dialog_message_card_was_wiped);
//            this.finish();
        } else {
            errorMessage = getResources().getString(R.string.nfc_aware_activity_error_dialog_message_unknown);
        }

        Toast.makeText(this, errorMessage, Toast.LENGTH_SHORT).show();
    }

    public void createKeyPreTap(String labelForKey) {
        // get a secure element session that is authenticated (authenticated session needed to add a key)
//        SecureElementApplet secureElementApplet = this.getSecureElementAppletPromptIfNeeded(true, true);
//        if (secureElementApplet == null) {
//            // there was no authenticated session established - the user is now being prompted to provide one, so just bail out for now
//            _logger.info("promptForLabelOKClicked: waiting for authenticated session");
//            _pendingAddKeyLabel = labelForKey;
//            return;
//        }
//
//        // otherwise we can just keep going and create the key
//        _logger.info("promptForLabelOKClicked: have authenticated session, creating key");
//        createKeyPostTap(secureElementApplet, labelForKey);
    }

    private void createKeyPostTap(SecureElementApplet secureElementApplet, String labelForKey) {
        _logger.info("generateKeyOnSecureElement: called");

//        PleaseWaitDialogFragment pleaseWaitDialogFragment = PleaseWaitDialogFragment.show(getSupportFragmentManager());
//        (new CreateKeyAsyncTask(secureElementApplet, pleaseWaitDialogFragment, labelForKey)).execute();
    }


    private class CheckKeysAsyncTask extends AsyncTask<Void, Void, IOException> {
        private SecureElementAppletImpl _secureElementApplet;
        private PleaseWaitDialogFragment _pleaseWaitDialogFragment;
        private String _password;
        private volatile byte[] _hashedPasswordBytes;
        public CheckKeysAsyncTask(SecureElementAppletImpl secureElementApplet, PleaseWaitDialogFragment pleaseWaitDialogFragment, String password) {
            _secureElementApplet = secureElementApplet;
            _pleaseWaitDialogFragment = pleaseWaitDialogFragment;
            _password = password;
        }

        @Override
        protected IOException doInBackground(Void... params) {

            try {

                _secureElementApplet.getAllData();

                Wallet newWallet = _secureElementApplet.getWallet();

                Wallet currentWallet = IntegrationConnector.getWallet(NFCAwareActivity.this);

                DeterministicKey newWalletDK = newWallet.getWatchingKey();
                DeterministicKey currentWalletDK = currentWallet.getWatchingKey();

                if (newWalletDK == null || currentWalletDK == null) {
                    _logger.info("------------------------------null Deterministic key");
                    return null;
                }

                if( newWalletDK.equals(currentWalletDK)) {
                    _logger.info("Wallets equal, not replacing wallet");
                } else {
                    _logger.info("Wallets not equal, replacing wallet");

                    IntegrationConnector.replaceWallet(NFCAwareActivity.this, newWallet);
                }

            } catch (IOException e) {
                _logger.error("checkkeys: exception:" + e.toString());
                return e;
            }

            return null;
        }

        @Override
        protected void onPostExecute(IOException e) {
            _pleaseWaitDialogFragment.dismiss();
            try {
                if (e == null) {
                    _logger.info("checkKeys: successful");
                    // logged in successfully
                    handleCardDetectedSuper(_secureElementApplet, true, true, _hashedPasswordBytes, _password);
                } else if (e instanceof IOException) {
                    // error while checking over the keys
                    _logger.info("checkKeys: failed to login");

                    // draw some UI for the user to indicate the error
                    showException(e);

                    // let the user try logging in again
//TODO: try again?
//                    showPromptForPasswordDialog();
                    return;
                }
            } finally {
                _password = null;
                _hashedPasswordBytes = null;
            }
        }

    }

    protected boolean showGetStartedDialogIfNeeded() {

        Wallet wallet = IntegrationConnector.getWallet(this);
        if (wallet != null ) {
            _logger.info("showGetStartedDialog: have a wallet, no ned for dialog");
            // Note: a dialog of this type may already be shown, it will have to be removed elsewhere
            return false;
        }

        FragmentManager fragmentManager = getFragmentManager();
        PromptForGetStartedDialogFragment promptForGetStartedDialogFragment = (PromptForGetStartedDialogFragment)fragmentManager.findFragmentByTag(PromptForGetStartedDialogFragment.TAG);
        if (promptForGetStartedDialogFragment != null) {
            // dialog is already showing, ignore this
            _logger.info("showGetStartedDialog: already showing get started dialog");
            return true;
        }

        PromptForGetStartedDialogFragment.prompt(fragmentManager);

        return true;
    }

    protected void hideGetStartedDialogIfNeeded() {
        _logger.info("hideGetStartedDialogIfNeeded: called");

        Wallet wallet = IntegrationConnector.getWallet(this);
        if (wallet !=  null) {
            FragmentManager fragmentManager = getFragmentManager();
            PromptForGetStartedDialogFragment promptForGetStartedDialogFragment = (PromptForGetStartedDialogFragment)fragmentManager.findFragmentByTag(PromptForGetStartedDialogFragment.TAG);
            if (promptForGetStartedDialogFragment != null) {
                _logger.info("hideGetStartedDialogIfNeeded: hiding dialog");
                promptForGetStartedDialogFragment.dismiss();
                return;
            }
        }
    }

    public void setupCardPrePreTap() {
        // get a secure element session that is authenticated (authenticated session needed to add a key)
        SecureElementApplet secureElementApplet = this.getSecureElementAppletPromptIfNeeded(true, true);
        if (secureElementApplet == null) {
            // there was no authenticated session established - the user is now being prompted to provide one, so just bail out for now
            _logger.info("setupCardPrePreTap: waiting for authenticated session");
            _pendingSetupCard = true;
            return;
        }

        // otherwise we can just keep going and create the key
        _logger.info("setupCardPrePreTap: have authenticated session, creating key");
        setupCardPrePostTap(secureElementApplet, null);
    }

    private void setupCardPrePostTap(SecureElementApplet secureElementApplet, String password) {
        _logger.info("setupCardPrePostTap: called");

        PleaseWaitDialogFragment pleaseWaitDialogFragment = PleaseWaitDialogFragment.show(getFragmentManager(), PleaseWaitDialogFragment.TYPE_CARD_SETUP);
        (new SetupCardAsyncTask(secureElementApplet, pleaseWaitDialogFragment, password)).execute();
    }

    private class SetupCardAsyncTask extends AsyncTask<Void, Void, IOException> {
        private SecureElementApplet _secureElementApplet;
        private PleaseWaitDialogFragment _pleaseWaitDialogFragment;
        private String _password;
        private volatile byte[] _hashedPasswordBytes;
        public SetupCardAsyncTask(SecureElementApplet secureElementApplet, PleaseWaitDialogFragment pleaseWaitDialogFragment, String password) {
            _secureElementApplet = secureElementApplet;
            _pleaseWaitDialogFragment = pleaseWaitDialogFragment;
            _password = password;
        }

        @Override
        protected IOException doInBackground(Void... params) {

            try {

                _secureElementApplet.setupCard();

                Wallet newWallet = _secureElementApplet.getWallet();

                Wallet currentWallet = IntegrationConnector.getWallet(NFCAwareActivity.this);

                DeterministicKey newWalletDK = newWallet.getWatchingKey();
                DeterministicKey currentWalletDK = (currentWallet == null) ? null : currentWallet.getWatchingKey();

                if (newWalletDK == null) {
                    _logger.info("smart card wallet not created");
                    return null;
                }

                if( newWalletDK.equals(currentWalletDK)) {
                    _logger.info("Wallets equal, not replacing wallet");
                } else {
                    _logger.info("Wallets not equal, replacing wallet");

                    IntegrationConnector.replaceWallet(NFCAwareActivity.this, newWallet);
                }

            } catch (IOException e) {
                _logger.error("checkkeys: exception:" + e.toString());
                return e;
            }

            return null;
        }

        @Override
        protected void onPostExecute(IOException e) {
            _pleaseWaitDialogFragment.dismiss();
            try {
                if (e == null) {
                    _logger.info("checkKeys: successful");
                    // card setup successfully
                    hideGetStartedDialogIfNeeded();
                    handleCardDetectedSuper(_secureElementApplet, true, true, _hashedPasswordBytes, _password);
                } else if (e instanceof IOException) {
                    // error while checking over the keys
                    _logger.error("setupCard failed");

                    // draw some UI for the user to indicate the error
                    showException(e);

                    // let the user try logging in again
//TODO: try again?
//                    showPromptForPasswordDialog();
                    return;
                }
            } finally {
                _password = null;
                _hashedPasswordBytes = null;
            }
        }

    }

    private class WipeCardAsyncTask extends AsyncTask<Void, Void, IOException> {
        private SecureElementApplet _secureElementApplet;
        private PleaseWaitDialogFragment _pleaseWaitDialogFragment;
        public WipeCardAsyncTask(SecureElementApplet secureElementApplet, PleaseWaitDialogFragment pleaseWaitDialogFragment) {
            _secureElementApplet = secureElementApplet;
            _pleaseWaitDialogFragment = pleaseWaitDialogFragment;
        }

        @Override
        protected IOException doInBackground(Void... params) {

            try {
                _secureElementApplet.wipeCard();
            } catch (IOException e) {
                return e;
            }

            return null;
        }

        @Override
        protected void onPostExecute(IOException e) {
            _pleaseWaitDialogFragment.dismiss();
            if (e == null) {
                _logger.info("wipeCard: successful");
                Toast.makeText(NFCAwareActivity.this, getResources().getString(R.string.wipe_success), Toast.LENGTH_LONG).show();
            } else if (e instanceof IOException) {
                // error while checking over the keys
                _logger.info("wipeCard: failed");

                // draw some UI for the user to indicate the error
                showException(e);
                return;
            }
        }
    }

    public void saveAntiMalwareKey(String key) {
        WalletGlobals.getInstance(this).setAntiMalwareKey(this, key);
        IntegrationConnector.ensureInfoFragmentIsUpdated(this);
        Toast.makeText(NFCAwareActivity.this, getResources().getString(R.string.anti_malware_key_set), Toast.LENGTH_LONG).show();
    }

    private void clearAntiMalwareKey() {
        WalletGlobals.getInstance(this).setAntiMalwareKey(this, null);
        IntegrationConnector.ensureInfoFragmentIsUpdated(this);
        Toast.makeText(NFCAwareActivity.this, getResources().getString(R.string.anti_malware_key_cleared), Toast.LENGTH_LONG).show();
    }
}
