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
    "io/ioutil"
    "net/http"
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

func getSANs(cert *x509.Certificate) []string {
    sans := cert.DNSNames
    // Also include the Common Name (CN) if it's not already in the SANs
    if cert.Subject.CommonName != "" {
        sans = append(sans, cert.Subject.CommonName)
    }
    return sans
}

func fetchCertificate(host string) (*x509.Certificate, error) {
    conn, err := tls.Dial("tcp", host, &tls.Config{
        InsecureSkipVerify: true,
    })
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    cert := conn.ConnectionState().PeerCertificates[0]
    return cert, nil
}

func readHostsFromFile(filename string) ([]string, error) {
    data, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    hosts := strings.Split(string(data), "\n")
    return hosts, nil
}

func filterSANs(sans []string, domain string) []string {
    var filtered []string
    for _, san := range sans {
        if strings.HasSuffix(san, domain) {
            filtered = append(filtered, san)
        }
    }
    return filtered
}

func integrateCRTSh(domain string) ([]string, error) {
    url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var crtshResults []map[string]interface{}
    err = json.NewDecoder(resp.Body).Decode(&crtshResults)
    if err != nil {
        return nil, err
    }

    subdomains := make(map[string]struct{})
    for _, result := range crtshResults {
        if name, ok := result["name_value"].(string); ok {
            subdomains[name] = struct{}{}
        }
    }

    uniqueSubdomains := make([]string, 0, len(subdomains))
    for subdomain := range subdomains {
        uniqueSubdomains = append(uniqueSubdomains, subdomain)
    }

    return uniqueSubdomains, nil
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

    uniqueSubdomains := make([]string, 0, len(subdomains))
    for subdomain := range subdomains {
        uniqueSubdomains = append(uniqueSubdomains, subdomain)
    }

    return uniqueSubdomains, nil
}

func processHost(host string, filterDomain string, includeCRTSh bool, wg *sync.WaitGroup, resultsChan chan<- Result) {
    defer wg.Done()

    if !strings.Contains(host, ":") {
        host += ":443"
    }

    cert, err := fetchCertificate(host)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error fetching certificate for %s: %v\n", host, err)
        return
    }

    sans := getSANs(cert)
    if filterDomain != "" {
        sans = filterSANs(sans, filterDomain)
    }

    if includeCRTSh && filterDomain != "" {
        crtShSubdomains, err := integrateCRTShPSQL(filterDomain)
        if err == nil {
            sans = append(sans, crtShSubdomains...)
        }
    }

    resultsChan <- Result{Host: host, SANs: sans}
}

func main() {
    var (
        hostsFile    string
        outputType   string
        filterDomain string
        includeCRTSh bool
        hostURLs     string
        rawOutput    bool
    )

    flag.StringVar(&hostsFile, "hosts", "", "File with list of hosts:port")
    flag.StringVar(&outputType, "output", "json", "Output format: csv or json")
    flag.StringVar(&filterDomain, "filter", "", "Filter out domain names that don't match the given domain")
    flag.BoolVar(&includeCRTSh, "crtsh", false, "Integrate with CRT.SH to extract more subdomains")
    flag.StringVar(&hostURLs, "u", "", "Comma-separated list of hosts:port")
    flag.BoolVar(&rawOutput, "raw", false, "Output only the extracted domains (hosts)")
    flag.Parse()

    var hosts []string
    if hostsFile != "" {
        fileHosts, err := readHostsFromFile(hostsFile)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error reading hosts file: %v\n", err)
            os.Exit(1)
        }
        hosts = append(hosts, fileHosts...)
    }

    if hostURLs != "" {
        hosts = append(hosts, strings.Split(hostURLs, ",")...)
    }

    if len(hosts) == 0 {
        // Read from stdin
        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
            hosts = append(hosts, scanner.Text())
        }
        if err := scanner.Err(); err != nil {
            fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
            os.Exit(1)
        }
    }

    if len(hosts) == 0 {
        fmt.Fprintln(os.Stderr, "No hosts provided")
        os.Exit(1)
    }

    var wg sync.WaitGroup
    resultsChan := make(chan Result, len(hosts))

    for _, host := range hosts {
        wg.Add(1)
        go processHost(host, filterDomain, includeCRTSh, &wg, resultsChan)
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
}
