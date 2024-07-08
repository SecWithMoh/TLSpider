package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	_ "github.com/lib/pq"
)

type Result struct {
	Host string   `json:"host"`
	SANs []string `json:"sans"`
}

var (
	outputType   string
	filterFile   string
	includeCRTSh bool
	rawOutput    bool
	ports        string
	silent       bool
	verbose      bool
)

func main() {

	flag.StringVar(&outputType, "output", "json", "Output format: csv or json")
	flag.StringVar(&filterFile, "filter", "", "File with list of domains for filtering")
	flag.BoolVar(&includeCRTSh, "crtsh", false, "Integrate with CRT.SH to extract more subdomains")
	flag.BoolVar(&rawOutput, "raw", false, "Output only the extracted domains (hosts)")
	flag.StringVar(&ports, "port", "443", "Ports to scan (comma-separated)")
	flag.BoolVar(&silent, "silent", false, "Silent mode (suppresses non-error messages)")
	flag.BoolVar(&verbose, "verbose", false, "Verbose mode (includes detailed messages)")
	flag.BoolVar(&verbose, "v", false, "Verbose mode (shorthand)")

	flag.Parse()

	portList := strings.Split(ports, ",")

	var targets []string
	if flag.NArg() > 0 {
		targets = flag.Args()
	} else {
		// Read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			targets = append(targets, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
			os.Exit(1)
		}
	}

	hosts, err := resolveHosts(targets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving hosts: %v\n", err)
		os.Exit(1)
	}

	var domains []string
	if filterFile != "" {
		filterDomains, err := readDomainsFromFile(filterFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading filter domains file: %v\n", err)
			os.Exit(1)
		}
		domains = filterDomains
	}

	var wg sync.WaitGroup
	resultsChan := make(chan Result, len(hosts))

	for _, host := range hosts {
		wg.Add(1)
		go processHost(host, portList, domains, includeCRTSh, &wg, resultsChan)
	}

	wg.Wait()
	close(resultsChan)

	var results []Result
	allSANs := make(map[string]struct{})

	for result := range resultsChan {
		for _, san := range result.SANs {
			allSANs[san] = struct{}{}
		}
		results = append(results, result)
	}

	uniqueSANs := make([]string, 0, len(allSANs))
	for san := range allSANs {
		uniqueSANs = append(uniqueSANs, san)
	}
	sort.Strings(uniqueSANs)

	if rawOutput {
		for _, san := range uniqueSANs {
			fmt.Println(san)
		}
	} else {
		switch outputType {
		case "csv":
			writer := csv.NewWriter(os.Stdout)
			defer writer.Flush()
			writer.Write([]string{"Host", "SANs"})
			for _, result := range results {
				writer.Write([]string{result.Host, strings.Join(result.SANs, ";")})
			}
			writer.Write([]string{"All SANs", strings.Join(uniqueSANs, ";")})
		case "json":
			data, err := json.MarshalIndent(results, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(data))

			allSANsData, err := json.MarshalIndent(uniqueSANs, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error marshaling JSON for all SANs: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("\nAll SANs:\n%s\n", string(allSANsData))
		default:
			fmt.Fprintf(os.Stderr, "Unsupported output format: %s\n", outputType)
			os.Exit(1)
		}
	}

	if silent && !verbose {
		return
	}

	// Print verbose information if enabled
	if verbose {
		printVerboseInfo(hosts, domains, includeCRTSh, results, uniqueSANs)
	}
}

func resolveHosts(targets []string) ([]string, error) {
	var hosts []string

	for _, target := range targets {
		if ip := net.ParseIP(target); ip != nil {
			hosts = append(hosts, target)
		} else if _, ipnet, err := net.ParseCIDR(target); err == nil {
			// It's a CIDR range, resolve all IPs in the range
			ips, err := resolveCIDR(ipnet)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, ips...)
		} else {
			// It's a domain name, resolve its IPs
			ipAddrs, err := net.LookupHost(target)
			if err != nil {
				return nil, err
			}
			hosts = append(hosts, ipAddrs...)
		}
	}

	return hosts, nil
}

func resolveCIDR(ipNet *net.IPNet) ([]string, error) {
	var ips []string

	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	// Remove network address and broadcast address
	if len(ips) > 0 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func readDomainsFromFile(filename string) ([]string, error) {
	var domains []string

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, strings.TrimSpace(scanner.Text()))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

func processHost(host string, ports []string, domains []string, includeCRTSh bool, wg *sync.WaitGroup, resultsChan chan<- Result) {
	defer wg.Done()

	var sans []string
	var cert *x509.Certificate
	var err error

	for _, port := range ports {
		fullHost := fmt.Sprintf("%s:%s", host, port)

		cert, err = fetchCertificate(fullHost)
		if err != nil {
			if strings.Contains(err.Error(), "EOF") {
				if !silent {
					fmt.Fprintf(os.Stderr, "Error fetching certificate for %s: %v\n", fullHost, err)
				}
				continue
			} else {
				fmt.Fprintf(os.Stderr, "Error fetching certificate for %s: %v\n", fullHost, err)
			}
			continue
		}

		sans = append(sans, getSANs(cert)...)
	}

	if len(sans) == 0 {
		if !silent {
			fmt.Fprintf(os.Stderr, "No certificates found for %s\n", host)
		}
		return
	}

	if len(domains) > 0 {
		sans = filterSANs(sans, domains)
	}

	if includeCRTSh && len(domains) > 0 {
		for _, domain := range domains {
			crtShSubdomains, err := integrateCRTShPSQL(domain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error integrating with CRT.SH for domain %s: %v\n", domain, err)
				continue
			}
			for _, subdomain := range crtShSubdomains {
				sans = append(sans, subdomain)
			}
		}
	}

	resultsChan <- Result{Host: host, SANs: sans}
}

func fetchCertificate(hostPort string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", hostPort, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Fetch the certificate
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificate found")
	}
	cert := state.PeerCertificates[0]

	return cert, nil
}

func getSANs(cert *x509.Certificate) []string {
	var sans []string

	for _, name := range cert.DNSNames {
		sans = append(sans, name)
	}

	return sans
}

func filterSANs(sans []string, domains []string) []string {
	var filtered []string

domainLoop:
	for _, s := range sans {
		for _, d := range domains {
			if strings.HasSuffix(s, d) {
				filtered = append(filtered, s)
				continue domainLoop
			}
		}
	}

	return filtered
}

func integrateCRTShPSQL(domain string) ([]string, error) {
	connStr := "host=crt.sh port=5432 user=guest dbname=certwatch sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	query := fmt.Sprintf(`
    SELECT DISTINCT ci.NAME_VALUE 
    FROM certificate_identity ci
    WHERE ci.NAME_VALUE LIKE '%%.%s'
`, domain)

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	subdomains := make(map[string]struct{})
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			return nil, err
		}
		subdomain = strings.ToLower(strings.TrimSpace(subdomain))
		subdomain = strings.TrimPrefix(subdomain, "*.")
		subdomains[subdomain] = struct{}{}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	var uniqueSubdomains []string
	for subdomain := range subdomains {
		uniqueSubdomains = append(uniqueSubdomains, subdomain)
	}

	return uniqueSubdomains, nil
}
func printVerboseInfo(hosts []string, domains []string, includeCRTSh bool, results []Result, uniqueSANs []string) {
	fmt.Println("\nVerbose Information:")
	fmt.Printf("Number of Hosts Scanned: %d\n", len(hosts))
	if len(domains) > 0 {
		fmt.Printf("Domains used for Filtering: %s\n", strings.Join(domains, ","))
	} else {
		fmt.Println("No filter domains specified.")
	}
	fmt.Printf("Include CRT.SH Integration: %v\n", includeCRTSh)
	fmt.Printf("Total Results Collected: %d\n", len(results))
	fmt.Printf("Total Unique SANs Found: %d\n", len(uniqueSANs))
}
