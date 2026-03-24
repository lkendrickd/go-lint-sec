package scan

import "regexp"

// Patterns for detecting blockchain-based command-and-control (C2) channels.
// Attackers use on-chain transaction memo fields as dead-drops to rotate
// payload URLs without modifying infected code.
var (
	reSolanaRPC    = regexp.MustCompile(`(?i)(api\.mainnet-beta\.solana\.com|api\.devnet\.solana\.com|api\.testnet\.solana\.com|solana-mainnet\.g\.alchemy\.com|solana\.public-rpc\.com)`)
	reSolanaAPI    = regexp.MustCompile(`(?i)(getSignaturesForAddress|get_signatures_for_address|getTransaction|get_transaction|getConfirmedTransaction|get_confirmed_transaction)`)
	reSolanaMemo   = regexp.MustCompile(`(?i)(memo|MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr|parsed.*memo|memo.*parsed|instruction.*memo|memo.*instruction)`)
	reSolanaImport = regexp.MustCompile(`(?i)(@solana/web3\.js|solana-py|solders|from\s+solana|from\s+solders|require\s*\(\s*['"]@solana)`)
	reEthRPC       = regexp.MustCompile(`(?i)(eth_call|eth_getTransactionByHash|eth_getLogs|eth_getTransactionReceipt|infura\.io|alchemy\.com/v2|web3\.eth)`)
	reEthImport    = regexp.MustCompile(`(?i)(from\s+web3|require\s*\(\s*['"]web3|require\s*\(\s*['"]ethers|from\s+ethers|import\s+.*ethers)`)
	reTxPoll       = regexp.MustCompile(`(?i)(setInterval|setTimeout|\.poll|polling|schedule).*?(transaction|getSignature|getTx|get_tx|memo|dead.?drop)`)
)

// ScanBlockchainC2 detects Solana and Ethereum RPC calls, SDK imports,
// memo/transaction field parsing, and polling patterns that may indicate
// blockchain-based C2 communication in non-blockchain projects.
func ScanBlockchainC2(line string, lineNum int, filePath string) []Finding {
	var findings []Finding
	checks := []struct {
		re     *regexp.Regexp
		detail string
	}{
		{reSolanaRPC, "Solana RPC endpoint reference"},
		{reSolanaAPI, "Solana transaction query API call"},
		{reSolanaMemo, "Solana memo program reference (potential dead-drop C2)"},
		{reSolanaImport, "Solana SDK import"},
		{reEthRPC, "Ethereum RPC call or provider reference"},
		{reEthImport, "Ethereum/web3 SDK import"},
		{reTxPoll, "transaction polling pattern (potential C2 check-in)"},
	}
	for _, c := range checks {
		if loc := c.re.FindStringIndex(line); loc != nil {
			findings = append(findings, Finding{
				File: filePath, Line: lineNum, Col: loc[0] + 1,
				Category: CategoryBlockchain,
				Detail:   c.detail,
			})
		}
	}
	return findings
}
