package scan

import (
	"strings"
	"testing"
)

func TestScanBlockchainC2(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantN   int
		wantSub string
	}{
		{
			"solana mainnet RPC",
			`const conn = new Connection("https://api.mainnet-beta.solana.com")`,
			1, "Solana RPC endpoint",
		},
		{
			"solana devnet RPC",
			`url = "https://api.devnet.solana.com"`,
			1, "Solana RPC endpoint",
		},
		{
			"getSignaturesForAddress",
			`const sigs = await conn.getSignaturesForAddress(pubkey)`,
			1, "Solana transaction query",
		},
		{
			"get_signatures_for_address python",
			`sigs = client.get_signatures_for_address(pubkey)`,
			1, "Solana transaction query",
		},
		{
			"solana web3 import",
			`const { Connection } = require("@solana/web3.js")`,
			1, "Solana SDK import",
		},
		{
			"python solana import",
			`from solana.rpc.api import Client`,
			1, "Solana SDK import",
		},
		{
			"ethereum RPC eth_call",
			`result = provider.send("eth_call", [params])`,
			1, "Ethereum RPC",
		},
		{
			"ethereum getLogs",
			`result = provider.send("eth_getLogs", [filter])`,
			1, "Ethereum RPC",
		},
		{
			"ethers import",
			`const { ethers } = require("ethers")`,
			1, "Ethereum/web3 SDK import",
		},
		{
			"web3 python import",
			`from web3 import Web3`,
			1, "Ethereum/web3 SDK import",
		},
		{
			"infura provider",
			`const url = "https://mainnet.infura.io/v3/key"`,
			1, "Ethereum RPC",
		},
		{
			"clean code no blockchain",
			`var x = fetchData("https://api.example.com")`,
			0, "",
		},
		{
			"clean import",
			`const fs = require("fs")`,
			0, "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanBlockchainC2(tt.line, 1, "test.js")
			if len(findings) != tt.wantN {
				t.Fatalf("findings = %d, want %d", len(findings), tt.wantN)
			}
			if tt.wantN > 0 && !strings.Contains(findings[0].Detail, tt.wantSub) {
				t.Errorf("detail = %q, want substring %q", findings[0].Detail, tt.wantSub)
			}
		})
	}
}

func TestScanBlockchainC2_TransactionPolling(t *testing.T) {
	lines := []string{
		`setInterval(() => checkTransaction(), 5000)`,
		`setTimeout(pollGetSignature, 1000)`,
		`scheduler.schedule(() => fetchMemo())`,
	}
	for _, line := range lines {
		findings := ScanBlockchainC2(line, 1, "test.js")
		found := false
		for _, f := range findings {
			if strings.Contains(f.Detail, "polling") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected polling finding for %q", line)
		}
	}
}
