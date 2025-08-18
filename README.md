# Go-OPReturn

A powerful Bitcoin CLI tool for creating and broadcasting Bitcoin transactions with OP_RETURN data using WIF private keys. Built with Go and featuring a modern, user-friendly interface.

## Features

- 🚀 **Easy OP_RETURN Creation** - Create Bitcoin transactions with custom data payloads
- 🔐 **WIF Private Key Support** - Works with standard WIF keys and Electrum p2wpkh format
- 💰 **Fixed 20% Fee Structure** - Transparent, predictable pricing with automatic network fee calculation
- 🌐 **Multi-Network Support** - Works with both Bitcoin mainnet and testnet
- 📡 **Real-time UTXO Management** - Live UTXO validation and refresh capabilities
- 📤 **Direct Transaction Broadcasting** - Send transactions directly to the Bitcoin network
- 🎨 **Beautiful CLI Interface** - Modern, colored output with clear information display
- 🛡️ **Built-in Safety Checks** - Dust threshold validation and UTXO availability verification

## Installation

### Prerequisites

- Go 1.19 or higher
- Git

### Build from Source

```bash
# Clone the repository
git clone https://github.com/slashbinslashnoname/go-opreturn.git
cd go-opreturn

# Build the binary
make build

# Or build manually
go build -o go-opreturn main.go
```

### Download Pre-built Binary

Pre-built binaries are available for various platforms in the [releases](https://github.com/slashbinslashnoname/go-opreturn/releases) section.

## Usage

### Basic Usage

```bash
# Run with default settings (mainnet)
./go-opreturn

# Specify network
./go-opreturn --network testnet
```

### Command Line Options

```bash
./go-opreturn [flags]

Flags:
  -n, --network string   Bitcoin network (mainnet or testnet) (default "mainnet")
  -h, --help            help for opreturner
```

### Interactive Workflow

1. **Select Network** - Choose between mainnet or testnet
2. **Enter WIF Key** - Provide your WIF private key (supports Electrum p2wpkh: prefix)
3. **Select UTXO** - Choose from available unspent transaction outputs
4. **Enter OP_RETURN Data** - Specify your custom data (max 80 bytes)
5. **Review & Confirm** - Check transaction details before creation
6. **Broadcast Transaction** - Send transaction directly to the Bitcoin network

## Fee Structure

Go-OPReturn uses a **fixed 20% fee structure**:

- **Service Fee**: 20% of the selected UTXO value
- **Network Fee**: Automatically calculated based on current mempool.space rates
- **Recipient Amount**: Service fee minus network fee
- **Change**: Remaining amount returned to your address

### Example

For a 10,000 satoshi UTXO:
- Service Fee: 2,000 satoshis (20%)
- Network Fee: ~500 satoshis (varies by network conditions)
- Recipient Amount: 1,500 satoshis
- Change: 7,500 satoshis

## Supported Networks

- **Mainnet** - Production Bitcoin network
- **Testnet** - Bitcoin test network for development and testing

## API Dependencies

Go-OPReturn uses the following external APIs:

- **mempool.space** - UTXO data, fee rate information, and transaction broadcasting
- **Mainnet**: `https://mempool.space/api`
- **Testnet**: `https://mempool.space/testnet/api`

## Security Features

- **UTXO Validation** - Multiple validation checks to ensure UTXO availability
- **Dust Threshold Protection** - Prevents creation of dust outputs
- **Live Status Checking** - Real-time verification before transaction creation
- **Network Fee Optimization** - Dynamic fee calculation based on current network conditions

## Technical Details

### OP_RETURN Implementation

- **Maximum Data Size**: 80 bytes
- **Output Type**: Null data script (OP_RETURN)
- **Transaction Structure**: 1 input, 3 outputs (recipient, OP_RETURN, change)

### Supported Address Types

- **SegWit (P2WPKH)** - Native SegWit addresses (bc1...)
- **Legacy WIF Keys** - Standard WIF private key format
- **Electrum Format** - p2wpkh: prefixed keys

### Transaction Signing

- **SegWit Support** - Native SegWit transaction signing
- **Witness Data** - Proper witness structure for SegWit transactions
- **Script Signature** - Empty scriptSig for SegWit inputs

### Transaction Broadcasting

- **Direct Broadcast** - Send transactions directly to the Bitcoin network
- **JSON Preview** - View transaction details before broadcasting
- **User Confirmation** - Simple y/N prompt for transaction confirmation
- **Fallback Support** - Manual broadcast instructions if automatic broadcast fails

## Development

### Project Structure

```
go-opreturn/
├── main.go          # Main application code
├── go.mod           # Go module dependencies
├── go.sum           # Go module checksums
├── Makefile         # Build and development tasks
└── README.md        # This file
```

### Dependencies

- **btcsuite/btcd** - Bitcoin protocol implementation
- **btcsuite/btcutil** - Bitcoin utility functions
- **charmbracelet/lipgloss** - Terminal styling
- **manifoldco/promptui** - Interactive prompts
- **spf13/cobra** - CLI framework

### Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Clean build artifacts
make clean

# Run tests
make test
```

## Troubleshooting

### Common Issues

1. **"No UTXOs available"**
   - Check if the address has confirmed transactions
   - Ensure you're using the correct network (mainnet/testnet)

2. **"UTXO validation failed"**
   - The selected UTXO may have been spent
   - Use the refresh option to get updated UTXO list

3. **"Dust threshold" errors**
   - UTXO value is too small (minimum 1000 satoshis)
   - Select a larger UTXO or wait for more confirmations

4. **"WIF key network mismatch"**
   - Ensure your WIF key matches the selected network
   - Use testnet keys for testnet, mainnet keys for mainnet

### Debug Information

The tool provides extensive debug output including:
- UTXO selection details
- Transaction structure information
- Fee calculations
- Validation steps

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Guidelines

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

**⚠️ Important Security Notice**

- This tool handles private keys - use with caution
- Always test with small amounts first
- Keep your private keys secure and never share them
- The authors are not responsible for any loss of funds
- Use at your own risk

## Support

If you need help or have questions:

- Open an issue on GitHub
- Check the troubleshooting section above
- Review the debug output for detailed information

## Roadmap

- [x] Direct transaction broadcasting
- [ ] Support for multiple UTXO inputs
- [ ] Batch transaction creation
- [ ] Custom fee rate selection
- [ ] Transaction template saving
- [ ] Integration with more Bitcoin APIs
- [ ] Web interface option

---

**Made with ❤️ for the Bitcoin community**
