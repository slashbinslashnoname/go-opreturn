package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/charmbracelet/lipgloss"
	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
)

// Version will be set by the Makefile during build
var Version = "dev"

var (
	// Styles for the interface
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFD700")).
			Padding(1, 0).
			MarginBottom(1)

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFA500"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000"))

	// Flags for the command
	network string
)

// Structure for UTXOs retrieved from mempool.space
type MempoolUTXO struct {
	Txid   string `json:"txid"`
	Vout   int    `json:"vout"`
	Status struct {
		Confirmed   bool   `json:"confirmed"`
		BlockHeight int64  `json:"block_height"`
		BlockTime   int64  `json:"block_time"`
		BlockHash   string `json:"block_hash"`
	} `json:"status"`
	Value int64 `json:"value"`
}

type MempoolAddressResponse struct {
	ChainStats struct {
		FundedTxoCount int64 `json:"funded_txo_count"`
		FundedTxoSum   int64 `json:"funded_txo_sum"`
		SpentTxoCount  int64 `json:"spent_txo_count"`
		SpentTxoSum    int64 `json:"spent_txo_sum"`
		TxCount        int64 `json:"tx_count"`
	} `json:"chain_stats"`
	MempoolStats struct {
		FundedTxoCount int64 `json:"funded_txo_count"`
		FundedTxoSum   int64 `json:"funded_txo_sum"`
		SpentTxoCount  int64 `json:"spent_txo_count"`
		SpentTxoSum    int64 `json:"spent_txo_sum"`
		TxCount        int64 `json:"tx_count"`
	} `json:"mempool_stats"`
	TxHistory []struct {
		Txid   string `json:"txid"`
		Vout   int    `json:"vout"`
		Status struct {
			Confirmed   bool   `json:"confirmed"`
			BlockHeight int64  `json:"block_height"`
			BlockTime   int64  `json:"block_time"`
			BlockHash   string `json:"block_hash"`
		} `json:"status"`
		Value int64 `json:"value"`
	} `json:"tx_history"`
}

// getAddressType returns a human-readable string describing the address type
func getAddressType(addr btcutil.Address) string {
	if _, ok := addr.(*btcutil.AddressWitnessPubKeyHash); ok {
		return "SegWit (P2WPKH)"
	}
	if _, ok := addr.(*btcutil.AddressPubKeyHash); ok {
		return "Legacy (P2PKH)"
	}
	if _, ok := addr.(*btcutil.AddressScriptHash); ok {
		return "P2SH"
	}
	if _, ok := addr.(*btcutil.AddressWitnessScriptHash); ok {
		return "SegWit (P2WSH)"
	}
	return "Unknown"
}

// decodeTransaction decodes a hex transaction and returns a JSON representation
func decodeTransaction(txHex string) (map[string]interface{}, error) {
	// Decode hex to bytes
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %v", err)
	}

	// Deserialize transaction
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
		return nil, fmt.Errorf("failed to deserialize transaction: %v", err)
	}

	// Calculate txid and hash
	txid := tx.TxHash().String()
	hash := tx.TxHash().String() // For non-SegWit transactions, hash == txid

	// Create the full JSON structure
	result := map[string]interface{}{
		"txid":     txid,
		"hash":     hash,
		"version":  tx.Version,
		"size":     len(txBytes),
		"vsize":    len(txBytes),     // Simplified for now
		"weight":   len(txBytes) * 4, // Simplified for now
		"locktime": tx.LockTime,
		"vin":      make([]map[string]interface{}, len(tx.TxIn)),
		"vout":     make([]map[string]interface{}, len(tx.TxOut)),
	}

	// Process inputs
	for i, input := range tx.TxIn {
		// Convert witness to string representation
		witnessStr := make([]string, len(input.Witness))
		for j, witnessItem := range input.Witness {
			witnessStr[j] = hex.EncodeToString(witnessItem)
		}

		result["vin"].([]map[string]interface{})[i] = map[string]interface{}{
			"txid":        input.PreviousOutPoint.Hash.String(),
			"vout":        input.PreviousOutPoint.Index,
			"sequence":    input.Sequence,
			"scriptSig":   map[string]string{"asm": "", "hex": hex.EncodeToString(input.SignatureScript)},
			"txinwitness": witnessStr,
		}
	}

	// Process outputs
	for i, output := range tx.TxOut {
		// Decode script to get type and address
		scriptClass, addresses, _, err := txscript.ExtractPkScriptAddrs(output.PkScript, &chaincfg.MainNetParams)
		if err != nil {
			scriptClass = txscript.NonStandardTy
		}

		var addr string
		if len(addresses) > 0 {
			addr = addresses[0].String()
		}

		// Get script assembly
		asm, err := txscript.DisasmString(output.PkScript)
		if err != nil {
			asm = ""
		}

		result["vout"].([]map[string]interface{})[i] = map[string]interface{}{
			"value": btcutil.Amount(output.Value).ToBTC(),
			"n":     i,
			"scriptPubKey": map[string]any{
				"asm":     asm,
				"hex":     hex.EncodeToString(output.PkScript),
				"type":    scriptClass.String(),
				"address": addr,
			},
		}
	}

	return result, nil
}

// broadcastTransaction sends a raw transaction to the network via mempool.space
func broadcastTransaction(txHex, apiBaseURL string) (string, error) {
	// Prepare the request
	url := fmt.Sprintf("%s/tx", apiBaseURL)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Create request
	req, err := http.NewRequest("POST", url, strings.NewReader(txHex))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "text/plain")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	// Check status code
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	// Return txid (response body contains the txid)
	txid := strings.TrimSpace(string(body))
	if len(txid) == 0 {
		return "", fmt.Errorf("empty txid received from API")
	}

	return txid, nil
}

func main() {
	// Root command with default execution
	rootCmd := &cobra.Command{
		Use:   "bitcoin-opreturn",
		Short: "A tool to create Bitcoin transactions with OP_RETURN",
		Long:  headerStyle.Render("Bitcoin OP_RETURN CLI") + "\nA tool to create and broadcast Bitcoin transactions with OP_RETURN data using WIF private keys.\nSupports P2PKH, P2WPKH, and other Bitcoin address schemes.\nFixed 20%% fee structure with non-changeable recipient address.\n",
		Run: func(cmd *cobra.Command, args []string) {
			createAndSendTx()
		},
	}

	// Flag for the network
	rootCmd.Flags().StringVarP(&network, "network", "n", "mainnet", "Bitcoin network (mainnet or testnet)")

	// Execute the command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, errorStyle.Render(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}
}

func createAndSendTx() {
	fmt.Println(headerStyle.Render("Creating a Bitcoin transaction with OP_RETURN"))
	fmt.Println(infoStyle.Render("Supports P2PKH, P2WPKH, and other Bitcoin address schemes"))
	fmt.Println(infoStyle.Render("Fixed 20% fee structure - recipient address cannot be changed"))

	// Network selection
	var netParams *chaincfg.Params
	var apiBaseURL string
	switch network {
	case "mainnet":
		netParams = &chaincfg.MainNetParams
		apiBaseURL = "https://mempool.space/api"
	case "testnet":
		netParams = &chaincfg.TestNet3Params
		apiBaseURL = "https://mempool.space/testnet/api"
	default:
		fmt.Println(errorStyle.Render("Error: unsupported network. Use 'mainnet' or 'testnet'."))
		os.Exit(1)
	}

	// Ask for WIF private key
	promptWIF := promptui.Prompt{
		Label: "WIF private key",
		Validate: func(input string) error {
			if len(input) == 0 {
				return fmt.Errorf("WIF key cannot be empty")
			}
			return nil
		},
	}
	wifString, err := promptWIF.Run()
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error when entering WIF key: %v", err)))
		os.Exit(1)
	}

	// Decode WIF private key (handle Electrum p2wpkh: prefix)
	var wif *btcutil.WIF

	if strings.HasPrefix(wifString, "p2wpkh:") {
		// Remove the p2wpkh: prefix and decode as WIF
		wifKey := strings.TrimPrefix(wifString, "p2wpkh:")
		wif, err = btcutil.DecodeWIF(wifKey)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error decoding WIF after removing p2wpkh: prefix: %v", err)))
			os.Exit(1)
		}
	} else {
		// Standard WIF format
		wif, err = btcutil.DecodeWIF(wifString)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error decoding WIF: %v", err)))
			os.Exit(1)
		}
	}

	// Check if WIF network matches selected network
	if !wif.IsForNet(netParams) {
		fmt.Println(errorStyle.Render("Warning: WIF key network does not match selected network"))
	}
	// Get private key from WIF
	privateKey := wif.PrivKey

	// Create address based on WIF type
	// Supported address schemes:
	// - Compressed WIF → SegWit (P2WPKH) address
	// - Uncompressed WIF → Legacy P2PKH address
	// Get public key and create address based on WIF type
	publicKey := privateKey.PubKey()
	var sourceAddr btcutil.Address

	// Detect address type from WIF and create appropriate address
	if wif.CompressPubKey {
		// Compressed public key - create SegWit address (P2WPKH)
		sourceAddr, err = btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(publicKey.SerializeCompressed()), netParams)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating SegWit address: %v", err)))
			os.Exit(1)
		}
		fmt.Println(infoStyle.Render("Detected compressed WIF - creating SegWit (P2WPKH) address"))
	} else {
		// Uncompressed public key - create legacy P2PKH address
		sourceAddr, err = btcutil.NewAddressPubKeyHash(btcutil.Hash160(publicKey.SerializeUncompressed()), netParams)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating P2PKH address: %v", err)))
			os.Exit(1)
		}
		fmt.Println(infoStyle.Render("Detected uncompressed WIF - creating legacy P2PKH address"))
	}

	addrString := sourceAddr.EncodeAddress()

	fmt.Println(infoStyle.Render(fmt.Sprintf("Source address (%s): %s", getAddressType(sourceAddr), addrString)))

	// Fetch UTXOs
	utxos, err := fetchUTXOs(addrString, apiBaseURL)
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error fetching UTXOs: %v", err)))
		os.Exit(1)
	}
	if len(utxos) == 0 {
		fmt.Println(errorStyle.Render("No UTXOs available for this address"))
		os.Exit(1)
	}

	// Select a UTXO
	selectedUTXO, err := selectUTXO(utxos)
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error selecting UTXO: %v", err)))
		os.Exit(1)
	}

	// Debug: Print the initially selected UTXO details
	fmt.Printf("DEBUG: Initially selected UTXO: TxID=%s, Vout=%d, Value=%d\n",
		selectedUTXO.Txid, selectedUTXO.Vout, selectedUTXO.Value)

	// Validate that the selected UTXO is still available
	fmt.Printf("Validating UTXO availability...\n")
	if err := validateUTXO(selectedUTXO, apiBaseURL); err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("UTXO validation failed: %v", err)))
		fmt.Println(errorStyle.Render("This UTXO may have been spent or is no longer available."))

		// Offer to refresh UTXOs
		promptRefresh := promptui.Prompt{
			Label:   "Would you like to refresh the UTXO list? (y/n)",
			Default: "y",
			Validate: func(input string) error {
				if input != "y" && input != "n" && input != "Y" && input != "N" {
					return fmt.Errorf("please enter 'y' or 'n'")
				}
				return nil
			},
		}

		refreshChoice, err := promptRefresh.Run()
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error: %v", err)))
			os.Exit(1)
		}

		if strings.ToLower(refreshChoice) == "y" {
			fmt.Println("Refreshing UTXO list...")
			utxos, err = refreshUTXOs(addrString, apiBaseURL)
			if err != nil {
				fmt.Println(errorStyle.Render(fmt.Sprintf("Error refreshing UTXOs: %v", err)))
				os.Exit(1)
			}
			if len(utxos) == 0 {
				fmt.Println(errorStyle.Render("No UTXOs available after refresh"))
				os.Exit(1)
			}

			// Select a new UTXO
			selectedUTXO, err = selectUTXO(utxos)
			if err != nil {
				fmt.Println(errorStyle.Render(fmt.Sprintf("Error selecting new UTXO: %v", err)))
				os.Exit(1)
			}

			// Debug: Print the selected UTXO details
			fmt.Printf("Selected new UTXO: TxID=%s, Vout=%d, Value=%d\n",
				selectedUTXO.Txid, selectedUTXO.Vout, selectedUTXO.Value)

			// Validate the new UTXO
			if err := validateUTXO(selectedUTXO, apiBaseURL); err != nil {
				fmt.Println(errorStyle.Render(fmt.Sprintf("New UTXO validation also failed: %v", err)))
				fmt.Println(errorStyle.Render("Please try again later or check your address balance."))
				os.Exit(1)
			}
			fmt.Println(infoStyle.Render("New UTXO validation successful"))
		} else {
			fmt.Println("Exiting due to UTXO validation failure.")
			os.Exit(1)
		}
	} else {
		fmt.Println(infoStyle.Render("UTXO validation successful"))
	}

	// Final validation check right before transaction creation to catch race conditions
	fmt.Printf("Performing final UTXO validation...\n")
	if err := validateUTXO(selectedUTXO, apiBaseURL); err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Final UTXO validation failed: %v", err)))
		fmt.Println(errorStyle.Render("This UTXO was spent between selection and transaction creation."))
		fmt.Println(errorStyle.Render("Please refresh the UTXO list and try again."))
		os.Exit(1)
	}
	fmt.Println(infoStyle.Render("Final UTXO validation successful"))

	// Fixed recipient address - no user input allowed
	// The recipient address supports all Bitcoin address formats (P2PKH, P2SH, P2WPKH, P2WSH)
	recipientAddr := "bc1qsqpwy7zp8uu6ld70g72lmmsntsv5qx74gwhur4"
	fmt.Printf("Recipient address (fixed): %s\n", infoStyle.Render(recipientAddr))

	// Ask for OP_RETURN data
	promptData := promptui.Prompt{
		Label: "OP_RETURN data (max 80 bytes)",
		Validate: func(input string) error {
			if len(input) > 80 {
				return fmt.Errorf("data exceeds 80 byte limit")
			}
			return nil
		},
	}
	data, err := promptData.Run()
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error when entering OP_RETURN data: %v", err)))
		os.Exit(1)
	}

	// Debug: Print the final selected UTXO details before transaction creation
	fmt.Printf("Creating transaction with UTXO: TxID=%s, Vout=%d, Value=%d\n",
		selectedUTXO.Txid, selectedUTXO.Vout, selectedUTXO.Value)

	// Fetch current fee rates from mempool.space
	fmt.Println("\nFetching current network fee rates...")
	feeRates, err := fetchFeeRates(apiBaseURL)
	if err != nil {
		fmt.Println(warningStyle.Render(fmt.Sprintf("Warning: Could not fetch fee rates: %v", err)))
		fmt.Println(warningStyle.Render("Using fallback fee calculation..."))
		feeRates = map[string]float64{"halfHourFee": 10.0} // Fallback rate
	}

	// Block UTXOs under 1000 sats (dust threshold)
	if selectedUTXO.Value < 1000 {
		fmt.Println(errorStyle.Render("Error: UTXO amount is too small (dust threshold)"))
		fmt.Printf("UTXO value: %d satoshis, Minimum required: 1000 satoshis\n", selectedUTXO.Value)
		fmt.Println("Bitcoin requires UTXOs under 1000 sats to have 0-fee transactions")
		fmt.Println("Please select a larger UTXO or wait for more confirmations")
		os.Exit(1)
	}

	// Calculate fixed 20% fee of UTXO amount
	feeAmount := selectedUTXO.Value * 20 / 100

	// Calculate dynamic transaction size based on OP_RETURN data and address type
	estimatedTxSize := calculateDynamicTxSize(data, wif.CompressPubKey)

	// Calculate dynamic network fee
	networkFee := calculateNetworkFee(feeRates, estimatedTxSize, selectedUTXO.Value)

	// Declare recipientAmount variable
	var recipientAmount int64

	// feeAmount go to recipient
	recipientAmount = feeAmount
	fmt.Printf("Fixed fee (20%%): %d satoshis\n", feeAmount)
	fmt.Printf("Network fee: %d satoshis\n", networkFee)
	fmt.Printf("Amount to recipient: %d satoshis\n", recipientAmount)

	// Check and adjust insufficient amounts
	if recipientAmount+networkFee > selectedUTXO.Value {
		fmt.Println(warningStyle.Render("Warning: Insufficient UTXO amount for desired outputs"))
		fmt.Printf("Required: %d satoshis, Available: %d satoshis\n",
			recipientAmount+networkFee, selectedUTXO.Value)

		// Reduce recipientAmount first
		recipientAmount = 0
		fmt.Println(infoStyle.Render("Recipient amount set to 0"))

		// If still insufficient, reduce fees
		if networkFee > selectedUTXO.Value {
			networkFee = selectedUTXO.Value
			fmt.Println(infoStyle.Render("Network fee reduced to UTXO amount"))
		}
	}

	// Display final amounts after adjustment
	fmt.Printf("Final amounts - Recipient: %d, Network Fee: %d\n", recipientAmount, networkFee)

	// Create a new transaction
	tx := wire.NewMsgTx(wire.TxVersion)

	fmt.Printf("Created transaction with %d inputs and %d outputs\n", len(tx.TxIn), len(tx.TxOut))

	// Debug: Verify selectedUTXO is valid before using it
	fmt.Printf("DEBUG: selectedUTXO details before transaction creation:\n")
	fmt.Printf("  TxID: %s\n", selectedUTXO.Txid)
	fmt.Printf("  Vout: %d\n", selectedUTXO.Vout)
	fmt.Printf("  Value: %d\n", selectedUTXO.Value)
	fmt.Printf("  Is zero value: %t\n", selectedUTXO.Value == 0)
	fmt.Printf("  TxID length: %d\n", len(selectedUTXO.Txid))

	// Validate UTXO data before proceeding
	if selectedUTXO.Txid == "" {
		fmt.Println(errorStyle.Render("ERROR: selectedUTXO.Txid is empty!"))
		os.Exit(1)
	}
	if selectedUTXO.Value <= 0 {
		fmt.Println(errorStyle.Render("ERROR: selectedUTXO.Value is invalid!"))
		os.Exit(1)
	}

	// Add the input (selected UTXO)
	fmt.Printf("Adding input: TxID=%s, Vout=%d\n", selectedUTXO.Txid, selectedUTXO.Vout)
	prevTxHash, err := hex.DecodeString(selectedUTXO.Txid)
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error decoding txid: %v", err)))
		os.Exit(1)
	}

	// Fix: Reverse the byte order for Bitcoin's little-endian format
	for i, j := 0, len(prevTxHash)-1; i < j; i, j = i+1, j-1 {
		prevTxHash[i], prevTxHash[j] = prevTxHash[j], prevTxHash[i]
	}

	hash, err := chainhash.NewHash(prevTxHash)
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating hash: %v", err)))
		os.Exit(1)
	}

	// Debug: Show the corrected hash
	fmt.Printf("DEBUG: Original TxID: %s\n", selectedUTXO.Txid)
	fmt.Printf("DEBUG: Corrected Hash: %s\n", hash.String())

	outPoint := wire.NewOutPoint(hash, uint32(selectedUTXO.Vout))
	txIn := wire.NewTxIn(outPoint, nil, nil)
	tx.AddTxIn(txIn)
	fmt.Printf("Added input. Transaction now has %d inputs\n", len(tx.TxIn))

	// Calculate change amount first
	changeAmount := selectedUTXO.Value - recipientAmount - networkFee

	// Determine dust threshold based on address type
	var dustThreshold int64
	if wif.CompressPubKey {
		// SegWit address (P2WPKH) - 546 sats
		dustThreshold = 330
	} else {
		// Legacy P2PKH address - 546 sats (same as SegWit in Bitcoin)
		dustThreshold = 546
	}

	if recipientAmount > 0 && recipientAmount < dustThreshold {
		fmt.Println(warningStyle.Render("Warning: Recipient amount is below dust threshold"))
		fmt.Printf("Recipient amount: %d satoshis, Dust threshold: %d satoshis\n", recipientAmount, dustThreshold)
		fmt.Println("Adjusting recipient amount to 0 to avoid dust output")
		recipientAmount = 0
		// Recalculate change amount
		changeAmount = selectedUTXO.Value - networkFee
	}

	if changeAmount > 0 && changeAmount < dustThreshold {
		fmt.Println(warningStyle.Render("Warning: Change amount is below dust threshold"))
		fmt.Printf("Change amount: %d satoshis, Dust threshold: %d satoshis\n", changeAmount, dustThreshold)
		fmt.Println("Adding change amount to network fee to avoid dust output")
		networkFee += changeAmount
		changeAmount = 0
	}

	// Add the recipient output (only if amount > 0)
	if recipientAmount > 0 {
		recipientAddress, err := btcutil.DecodeAddress(recipientAddr, netParams)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error decoding recipient address: %v", err)))
			os.Exit(1)
		}

		recipientScript, err := txscript.PayToAddrScript(recipientAddress)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating recipient script: %v", err)))
			os.Exit(1)
		}
		txOutRecipient := wire.NewTxOut(recipientAmount, recipientScript)
		tx.AddTxOut(txOutRecipient)
	}

	// Add the OP_RETURN output
	opReturnData := []byte(data)
	opReturnScript, err := txscript.NullDataScript(opReturnData)
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating OP_RETURN script: %v", err)))
		os.Exit(1)
	}
	txOutOPReturn := wire.NewTxOut(0, opReturnScript)
	tx.AddTxOut(txOutOPReturn)

	// Add the change output (only if amount > 0)
	var changeScript []byte
	if changeAmount > 0 {
		changeScript, err = txscript.PayToAddrScript(sourceAddr)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating change script: %v", err)))
			os.Exit(1)
		}
		txOutChange := wire.NewTxOut(changeAmount, changeScript)
		tx.AddTxOut(txOutChange)
		fmt.Printf("Added change output: %d satoshis\n", changeAmount)
	} else {
		fmt.Println(infoStyle.Render("No change output needed (amount below dust threshold or zero)"))
	}

	// Sign the transaction based on address type
	if wif.CompressPubKey {
		// SegWit address (P2WPKH) - use witness signature
		fmt.Println(infoStyle.Render("Signing transaction for SegWit address..."))
		sigHashes := txscript.NewTxSigHashes(tx)

		// Use change script if exists, otherwise use OP_RETURN script for signing
		signingScript := changeScript
		if len(signingScript) == 0 {
			// No change output, use OP_RETURN script for signing
			signingScript, err = txscript.NullDataScript([]byte(data))
			if err != nil {
				fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating OP_RETURN script for signing: %v", err)))
				os.Exit(1)
			}
		}

		witness, err := txscript.WitnessSignature(tx, sigHashes, 0, selectedUTXO.Value, signingScript, txscript.SigHashAll, privateKey, true)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating witness signature: %v", err)))
			os.Exit(1)
		}

		// Set the witness data (required for SegWit)
		tx.TxIn[0].Witness = witness

		// For SegWit, scriptSig should be empty
		tx.TxIn[0].SignatureScript = nil
	} else {
		// Legacy P2PKH address - use traditional signature
		fmt.Println(infoStyle.Render("Signing transaction for legacy P2PKH address..."))

		// Use change script if exists, otherwise use OP_RETURN script for signing
		signingScript := changeScript
		if len(signingScript) == 0 {
			// No change output, use OP_RETURN script for signing
			signingScript, err = txscript.NullDataScript([]byte(data))
			if err != nil {
				fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating OP_RETURN script for signing: %v", err)))
				os.Exit(1)
			}
		}

		// Create the signature script for P2PKH
		sigScript, err := txscript.SignatureScript(tx, 0, signingScript, txscript.SigHashAll, privateKey, true)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Error creating signature script: %v", err)))
			os.Exit(1)
		}

		// Set the signature script for legacy transactions
		tx.TxIn[0].SignatureScript = sigScript

		// For legacy transactions, witness should be nil
		tx.TxIn[0].Witness = nil
	}

	// Debug: Verify transaction structure before serialization
	fmt.Printf("Transaction structure before serialization:\n")
	fmt.Printf("  Inputs: %d\n", len(tx.TxIn))
	for i, input := range tx.TxIn {
		fmt.Printf("    Input %d: TxID=%s, Vout=%d, ScriptLen=%d\n",
			i, input.PreviousOutPoint.Hash.String(), input.PreviousOutPoint.Index, len(input.SignatureScript))
	}
	fmt.Printf("  Outputs: %d\n", len(tx.TxOut))
	for i, output := range tx.TxOut {
		fmt.Printf("    Output %d: Value=%d, ScriptLen=%d\n", i, output.Value, len(output.PkScript))
	}

	// Serialize the transaction
	var txBuf bytes.Buffer
	if err := tx.Serialize(&txBuf); err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error serializing transaction: %v", err)))
		os.Exit(1)
	}
	txHex := hex.EncodeToString(txBuf.Bytes())

	// Display information
	fmt.Println(infoStyle.Render("Transaction created successfully!"))
	fmt.Printf("Source address: %s\n", infoStyle.Render(addrString))
	fmt.Printf("Recipient address: %s\n", infoStyle.Render(recipientAddr))
	fmt.Printf("Fixed fee (20%%): %d satoshis\n", feeAmount)
	fmt.Printf("Network fee: %d satoshis\n", networkFee)
	fmt.Printf("Amount to recipient: %d satoshis\n", recipientAmount)
	fmt.Printf("OP_RETURN data: %s\n", infoStyle.Render(string(opReturnData)))
	fmt.Printf("Change amount: %d satoshis\n", changeAmount)
	fmt.Printf("Transaction (hex): %s\n", infoStyle.Render(txHex))

	// Final UTXO validation right before broadcast attempt
	fmt.Println("\nPerforming final UTXO validation before broadcast...")
	if err := liveUTXOCheck(selectedUTXO, apiBaseURL, addrString); err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("CRITICAL: Final UTXO validation failed: %v", err)))
		fmt.Println(errorStyle.Render("This UTXO is no longer available for spending."))
		fmt.Println(errorStyle.Render("The transaction will fail if broadcast. Please refresh UTXOs and try again."))
		os.Exit(1)
	}
	fmt.Println(infoStyle.Render("Final UTXO validation successful - UTXO is still available"))

	// Decode and display transaction details
	fmt.Println("\n" + headerStyle.Render("Transaction Details"))
	txData, err := decodeTransaction(txHex)
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error decoding transaction: %v", err)))
		os.Exit(1)
	}

	// Pretty print JSON
	txJSON, err := json.MarshalIndent(txData, "", "  ")
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error formatting transaction JSON: %v", err)))
		os.Exit(1)
	}
	fmt.Println(string(txJSON))

	// Ask for broadcast confirmation
	promptBroadcast := promptui.Prompt{
		Label: "Broadcast transaction? (y/N)",
		Validate: func(input string) error {
			if input != "y" && input != "n" && input != "Y" && input != "N" && input != "" {
				return fmt.Errorf("please enter 'y' or 'n'")
			}
			return nil
		},
	}

	broadcastChoice, err := promptBroadcast.Run()
	if err != nil {
		fmt.Println(errorStyle.Render(fmt.Sprintf("Error: %v", err)))
		os.Exit(1)
	}

	if strings.ToLower(broadcastChoice) == "y" {
		fmt.Println("\nBroadcasting transaction to network...")

		txid, err := broadcastTransaction(txHex, apiBaseURL)
		if err != nil {
			fmt.Println(errorStyle.Render(fmt.Sprintf("Broadcast failed: %v", err)))
			fmt.Println(errorStyle.Render("You can still broadcast manually using:"))
			fmt.Println(infoStyle.Render(fmt.Sprintf("bitcoin-cli sendrawtransaction %s", txHex)))
			os.Exit(1)
		}

		fmt.Println(infoStyle.Render("Transaction broadcast successfully!"))
		fmt.Printf("Txid: %s\n", infoStyle.Render(txid))
		fmt.Printf("View on mempool.space: %s/tx/%s\n", apiBaseURL, txid)
	} else {
		fmt.Println(infoStyle.Render("Transaction not broadcast. You can broadcast manually using:"))
		fmt.Println(infoStyle.Render(fmt.Sprintf("bitcoin-cli sendrawtransaction %s", txHex)))
	}

}

// fetchFeeRates retrieves current fee rates from mempool.space
func fetchFeeRates(apiBaseURL string) (map[string]float64, error) {
	url := fmt.Sprintf("%s/v1/fees/recommended", apiBaseURL)
	fmt.Printf("Fetching fee rates from: %s\n", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status code: %d", resp.StatusCode)
	}

	var feeRates map[string]float64
	if err := json.NewDecoder(resp.Body).Decode(&feeRates); err != nil {
		return nil, fmt.Errorf("JSON decode failed: %v", err)
	}

	fmt.Printf("Current fee rates: Fast=%v, HalfHour=%v, Hour=%v sat/vB\n",
		feeRates["fastestFee"], feeRates["halfHourFee"], feeRates["hourFee"])

	return feeRates, nil
}

// calculateNetworkFee calculates the network fee based on current mempool.space rates
func calculateNetworkFee(feeRates map[string]float64, txSize int, availableAmount int64) int64 {
	// Use halfHourFee for a good balance between speed and cost
	feeRate := feeRates["halfHourFee"]
	if feeRate == 0 {
		// Fallback to hourFee if halfHourFee is not available
		feeRate = feeRates["hourFee"]
	}
	if feeRate == 0 {
		// Fallback to fastestFee if hourFee is not available
		feeRate = feeRates["fastestFee"]
	}
	if feeRate == 0 {
		// Ultimate fallback to a reasonable default
		feeRate = 3.0
	}

	// Calculate fee: fee rate (sat/vB) * transaction size (vB)
	networkFee := int64(feeRate * float64(txSize))

	// Ensure minimum fee of 200 sats ONLY if calculated fee is below minimum
	if networkFee < 200 {
		networkFee = 200
	}

	// Ensure we don't exceed available amount
	if networkFee > availableAmount {
		networkFee = availableAmount - 100 // Leave buffer for recipient
	}

	fmt.Printf("Calculated network fee: %d satoshis (%.2f sat/vB × %d vB)\n", networkFee, feeRate, txSize)
	return networkFee
}

// calculateDynamicTxSize calculates transaction size based on OP_RETURN data and address type
func calculateDynamicTxSize(data string, isSegWit bool) int {
	// Calculate OP_RETURN size: OP_RETURN (1) + length (1) + data (N)
	opReturnSize := 1 + 1 + len(data)

	// Base transaction size according to address type
	baseSize := 200 // SegWit (P2WPKH) - smaller due to witness data
	if !isSegWit {
		baseSize = 300 // Legacy (P2PKH) - larger due to signature scripts
	}

	return baseSize + opReturnSize
}

// fetchUTXOs retrieves available UTXOs for an address via mempool.space
func fetchUTXOs(address, apiBaseURL string) ([]MempoolUTXO, error) {
	url := fmt.Sprintf("%s/address/%s/utxo", apiBaseURL, address)
	fmt.Printf("Fetching UTXOs from: %s\n", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("API returned status code: %d", resp.StatusCode)
	}

	var utxos []MempoolUTXO
	if err := json.NewDecoder(resp.Body).Decode(&utxos); err != nil {
		return nil, fmt.Errorf("JSON decode failed: %v", err)
	}

	fmt.Printf("Found %d UTXOs\n", len(utxos))

	return utxos, nil
}

// selectUTXO allows the user to choose a UTXO via an interactive interface
func selectUTXO(utxos []MempoolUTXO) (MempoolUTXO, error) {
	// Filter out dust UTXOs (under 1000 sats)
	var validUTXOs []MempoolUTXO
	var dustCount int
	for _, utxo := range utxos {
		if utxo.Value >= 1000 {
			validUTXOs = append(validUTXOs, utxo)
		} else {
			dustCount++
		}
	}

	if dustCount > 0 {
		fmt.Printf(warningStyle.Render("Warning: Filtered out %d dust UTXOs (under 1000 sats)\n"), dustCount)
		fmt.Println(warningStyle.Render("Bitcoin requires UTXOs under 1000 sats to have 0-fee transactions"))
	}

	if len(validUTXOs) == 0 {
		return MempoolUTXO{}, fmt.Errorf("no UTXOs with sufficient value (minimum 1000 sats required)")
	}

	fmt.Println(headerStyle.Render("Available UTXOs"))
	items := make([]string, len(validUTXOs))
	for i, utxo := range validUTXOs {
		items[i] = fmt.Sprintf("TxID: %s, Vout: %d, Amount: %d satoshis", utxo.Txid, utxo.Vout, utxo.Value)
	}

	prompt := promptui.Select{
		Label: "Select a UTXO",
		Items: items,
	}

	index, _, err := prompt.Run()
	if err != nil {
		return MempoolUTXO{}, err
	}

	return validUTXOs[index], nil
}

// validateUTXO checks if a UTXO is still available on the mempool.space API
func validateUTXO(utxo MempoolUTXO, apiBaseURL string) error {
	// Check if the transaction output is still unspent using the outspend API
	outspendURL := fmt.Sprintf("%s/tx/%s/outspend/%d", apiBaseURL, utxo.Txid, utxo.Vout)

	// Try validation up to 3 times with small delays to handle mempool race conditions
	for attempt := 1; attempt <= 3; attempt++ {
		if attempt > 1 {
			fmt.Printf("Validation attempt %d (retrying due to potential race condition)...\n", attempt)
			time.Sleep(2 * time.Second) // Wait 2 seconds between attempts
		}

		resp, err := http.Get(outspendURL)
		if err != nil {
			if attempt == 3 {
				return fmt.Errorf("failed to check UTXO status after 3 attempts: %v", err)
			}
			continue
		}

		if resp.StatusCode == 404 {
			return fmt.Errorf("UTXO %s:%d not found (may have been spent)", utxo.Txid, utxo.Vout)
		}

		if resp.StatusCode != 200 {
			if attempt == 3 {
				return fmt.Errorf("API returned status %d for UTXO %s:%d after 3 attempts", resp.StatusCode, utxo.Txid, utxo.Vout)
			}
			resp.Body.Close()
			continue
		}

		var outspendResponse struct {
			Spent bool `json:"spent"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&outspendResponse); err != nil {
			resp.Body.Close()
			if attempt == 3 {
				return fmt.Errorf("failed to decode UTXO status after 3 attempts: %v", err)
			}
			continue
		}

		resp.Body.Close()

		if outspendResponse.Spent {
			return fmt.Errorf("UTXO %s:%d is spent", utxo.Txid, utxo.Vout)
		}

		// If we get here, the UTXO is valid
		if attempt > 1 {
			fmt.Printf("UTXO validation succeeded on attempt %d\n", attempt)
		}
		fmt.Printf("UTXO %s:%d is still available with %d satoshis.\n", utxo.Txid, utxo.Vout, utxo.Value)
		return nil
	}

	return fmt.Errorf("UTXO validation failed after 3 attempts")
}

// refreshUTXOs fetches fresh UTXO data for an address
func refreshUTXOs(address, apiBaseURL string) ([]MempoolUTXO, error) {
	fmt.Printf("Refreshing UTXOs for address: %s\n", address)
	return fetchUTXOs(address, apiBaseURL)
}

// liveUTXOCheck performs an immediate, aggressive check of UTXO availability
func liveUTXOCheck(utxo MempoolUTXO, apiBaseURL, sourceAddress string) error {
	fmt.Printf("Performing live UTXO check for %s:%d...\n", utxo.Txid, utxo.Vout)

	// Check multiple endpoints for maximum reliability
	endpoints := []string{
		fmt.Sprintf("%s/tx/%s/outspend/%d", apiBaseURL, utxo.Txid, utxo.Vout),
		fmt.Sprintf("%s/address/%s/utxo", apiBaseURL, sourceAddress),
	}

	for i, endpoint := range endpoints {
		if i == 0 {
			// First endpoint: direct outspend check
			resp, err := http.Get(endpoint)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				var outspend struct {
					Spent bool `json:"spent"`
				}
				if json.NewDecoder(resp.Body).Decode(&outspend) == nil {
					resp.Body.Close()
					if outspend.Spent {
						return fmt.Errorf("UTXO %s:%d is confirmed as spent", utxo.Txid, utxo.Vout)
					}
				}
			}
			resp.Body.Close()
		} else {
			// Second endpoint: verify UTXO is still in address list
			resp, err := http.Get(endpoint)
			if err != nil {
				continue
			}

			if resp.StatusCode == 200 {
				var currentUTXOs []MempoolUTXO
				if json.NewDecoder(resp.Body).Decode(&currentUTXOs) == nil {
					resp.Body.Close()
					// Check if our UTXO is still in the list
					found := false
					for _, currentUTXO := range currentUTXOs {
						if currentUTXO.Txid == utxo.Txid && currentUTXO.Vout == utxo.Vout {
							found = true
							if currentUTXO.Value != utxo.Value {
								return fmt.Errorf("UTXO %s:%d value changed from %d to %d",
									utxo.Txid, utxo.Vout, utxo.Value, currentUTXO.Value)
							}
							break
						}
					}
					if !found {
						return fmt.Errorf("UTXO %s:%d no longer appears in address UTXO list", utxo.Txid, utxo.Vout)
					}
				}
			}
			resp.Body.Close()
		}
	}

	fmt.Printf("Live UTXO check passed for %s:%d\n", utxo.Txid, utxo.Vout)
	return nil
}
