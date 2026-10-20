package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	flag "github.com/spf13/pflag"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := runCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, cliServices{})
	stop()
	os.Exit(code)
}

// runCLI owns argument parsing and exit-code policy; execution never exits the process.
func runCLI(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, services cliServices) int {
	flags := flag.NewFlagSet("full-reverse", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var (
		dnsServers           stringList
		quiet                bool
		inputFiles           stringList
		forwardConfirmedOnly bool
		lookupAS             bool
		concurrency          int
		retries              int
		rate, resolverRate   int
		timeout              time.Duration
	)

	flags.VarP(&dnsServers, "dns-server", "d", "DNS server to use (e.g. 8.8.8.8:53); repeatable, defaults to system resolver")
	flags.VarP(&inputFiles, "input", "i", "read targets from a file, one per line; use - for stdin")
	flags.BoolVarP(&quiet, "quiet", "q", false, "silence progress and summary logging")
	flags.BoolVarP(&lookupAS, "lookup-as", "a", false, "look up the announcing ASN for IPs whose ASN is not already known")
	flags.BoolVarP(&forwardConfirmedOnly, "forward-confirmed-only", "f", false, "only report PTR records whose name resolves back to the same IP")
	flags.IntVarP(&concurrency, "concurrency", "c", 32, "maximum active DNS attempts or ASN preparation steps")
	flags.IntVarP(&retries, "retries", "r", 4, "retries for timeouts and I/O errors (NXDOMAIN is never retried)")
	flags.IntVar(&rate, "rate", 0, "maximum total DNS sends/second (0 disables pacing)")
	flags.IntVar(&resolverRate, "resolver-rate", 0, "maximum DNS sends/second per configured resolver (0 disables pacing)")
	flags.DurationVarP(&timeout, "timeout", "t", 2500*time.Millisecond, "per-attempt lookup timeout")

	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: full-reverse [options] [target...]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Targets are IPv4 CIDRs, IPs, ASNs (AS15169), AS names (AMAZON-AES), or files containing them.")
		fmt.Fprintln(stderr, "A target of - reads targets from stdin.")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Options:")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}

	if concurrency < 1 {
		fmt.Fprintln(stderr, "error: concurrency must be >= 1")
		return 2
	}
	if retries < 0 {
		fmt.Fprintln(stderr, "error: retry count must be >= 0")
		return 2
	}

	if err := validateRates(rate, resolverRate); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
	inputs, err := readInputs(ctx, stdin, flags.Args(), inputFiles)
	if err == nil {
		err = runLookups(ctx, lookupOptions{
			rate: rate, resolverRate: resolverRate, dnsServers: dnsServers, concurrency: concurrency, retries: retries,
			timeout: timeout, lookupAS: lookupAS, forwardConfirmedOnly: forwardConfirmedOnly, quiet: quiet,
		}, inputs, stdout, stderr, services)
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Type() string { return "string" }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
