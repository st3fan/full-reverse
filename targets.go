package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/st3fan/full-reverse/ripestat"
)

// readInputs collects targets from explicit input files, positional arguments,
// and (when nothing else is given) stdin. Values in input files and stdin are
// one target (CIDR, plain IP, ASN, or AS name) per line, though whitespace/comma
// separated values and '#' comments are also accepted. A positional argument
// that names an existing file is read as a list of targets; any other
// positional argument is treated as a literal CIDR, IP, or ASN. An input file
// of "-" reads stdin.
func readInputs(ctx context.Context, stdin io.Reader, args, inputFiles []string) ([]string, error) {
	var inputs []string

	for _, path := range inputFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if path == "-" {
			var err error
			inputs, err = scanCIDRs(ctx, stdin, inputs)
			if err != nil {
				return nil, err
			}
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening input file %q: %w", path, err)
		}
		inputs, err = scanCIDRs(ctx, f, inputs)
		f.Close()
		if err != nil {
			return nil, err
		}
	}

	for _, arg := range args {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if arg == "-" {
			var err error
			inputs, err = scanCIDRs(ctx, stdin, inputs)
			if err != nil {
				return nil, err
			}
			continue
		}
		f, err := os.Open(arg)
		if err != nil {
			// Not a readable file: treat the argument as a literal CIDR, IP, or ASN.
			inputs = append(inputs, arg)
			continue
		}
		inputs, err = scanCIDRs(ctx, f, inputs)
		f.Close()
		if err != nil {
			return nil, err
		}
	}

	// With no explicit sources, read the target list from stdin.
	if len(args) == 0 && len(inputFiles) == 0 {
		var err error
		inputs, err = scanCIDRs(ctx, stdin, inputs)
		if err != nil {
			return nil, err
		}
	}

	if len(inputs) == 0 {
		return nil, fmt.Errorf("no CIDRs, IPs, or ASNs provided")
	}
	return inputs, nil
}

// scanCIDRs appends targets read from r to inputs. On cancellation it closes
// closable readers to interrupt blocked input; normal completion leaves them open.
// Other readers must arrange for their Read method to return on cancellation.
func scanCIDRs(ctx context.Context, r io.Reader, inputs []string) ([]string, error) {
	if closer, ok := r.(io.Closer); ok {
		stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
		defer stop()
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for ctx.Err() == nil && sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.ReplaceAll(line, ",", " ")
		inputs = append(inputs, strings.Fields(line)...)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return inputs, nil
}

// pickASN chooses a single ASN from RIPE Stat search matches, preferring an
// exact as-name match and rejecting ambiguous names.
func pickASN(name string, matches []ripestat.ASMatch) (ripestat.ASMatch, error) {
	var exact []ripestat.ASMatch
	for _, m := range matches {
		if strings.EqualFold(m.Name, name) {
			exact = append(exact, m)
		}
	}

	switch {
	case len(exact) == 1:
		return exact[0], nil
	case len(matches) == 1:
		return matches[0], nil
	default:
		if len(exact) > 1 {
			matches = exact
		}
		labels := make([]string, len(matches))
		for i, m := range matches {
			labels[i] = fmt.Sprintf("AS%d (%s)", m.ASN, m.Name)
		}
		return ripestat.ASMatch{}, fmt.Errorf("ambiguous AS name %q matches %s; use an AS number", name, strings.Join(labels, ", "))
	}
}

// asRequest is an AS to expand, remembering how the user wrote it.
type asRequest struct {
	resource string // canonical "AS<number>"
	label    string // target as given by the user
}

// resolveTargets converts a mixed list of CIDRs, plain IPs, ASNs, and AS names
// into scan targets. A plain IP is treated as a /32. ASNs ("AS15169",
// "as15169", or bare "15169") are expanded to their announced prefixes via the
// RIPE Stat API, and each such target records the ASN it came from. An AS name
// such as "AMAZON-AES" is resolved to an ASN first, and is rejected when it
// matches more than one AS.
func resolveTargets(ctx context.Context, client ripeClient, inputs []string, log logFunc) ([]target, error) {
	var targets []target
	var asRequests []asRequest

	for _, in := range inputs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if p, err := netip.ParsePrefix(in); err == nil {
			if !p.Addr().Is4() {
				return nil, fmt.Errorf("only IPv4 CIDRs are supported: %q", in)
			}
			targets = append(targets, target{label: in, prefix: p.Masked()})
			continue
		}
		if a, err := netip.ParseAddr(in); err == nil {
			a = a.Unmap()
			if !a.Is4() {
				return nil, fmt.Errorf("only IPv4 addresses are supported: %q", in)
			}
			targets = append(targets, target{label: in, prefix: netip.PrefixFrom(a, 32)})
			continue
		}
		if resource, err := ripestat.NormalizeASN(in); err == nil {
			asRequests = append(asRequests, asRequest{resource: resource, label: in})
			continue
		}

		// Otherwise treat the token as an AS name (e.g. AMAZON-AES).
		matches, err := client.SearchASNs(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("resolving AS name %q: %w", in, err)
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("invalid CIDR, IP, ASN, or AS name %q", in)
		}
		match, err := pickASN(in, matches)
		if err != nil {
			return nil, err
		}
		log.printf("%s resolved to AS%d (%s)", in, match.ASN, match.Description)
		asRequests = append(asRequests, asRequest{resource: fmt.Sprintf("AS%d", match.ASN), label: in})
	}

	for _, req := range asRequests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		number, err := ripestat.ASNNumber(req.resource)
		if err != nil {
			return nil, err
		}
		info, err := client.ASOverview(ctx, req.resource)
		if err != nil {
			return nil, err
		}
		announced, err := client.AnnouncedPrefixes(ctx, req.resource)
		if err != nil {
			return nil, err
		}
		list := make([]string, len(announced))
		for i, p := range announced {
			list[i] = p.String()
		}
		log.printf("%s: %d announced IPv4 prefix(es): %s", req.resource, len(announced), strings.Join(list, ", "))
		for _, p := range announced {
			targets = append(targets, target{label: req.label, prefix: p, asn: number, asName: info.Name, asOrg: info.Org})
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no CIDRs, IPs, or ASNs provided")
	}
	return targets, nil
}
