# TLSpider 🕷️

TLSpider is a tool written in Go for extracting Subject Alternative Names (SANs) found in SSL Certificates directly from HTTPS websites. It provides automation for gathering DNS names (subdomains) and virtual servers from SSL certificates.

## Features ✨

- 🗂 Extracts SANs from SSL certificates of HTTPS websites.
- 📄 Supports output in CSV or JSON formats for easy integration with other tools.
- 🔍 Filters out domain names that don't match the specified domain.
- 🔗 Integrates with CRT.SH to extract additional subdomains from the same entity's certificates.
- 🔒 Works with both publicly trusted certificates and self-signed certificates.
- 🛠 Allows specifying multiple ports.
- 📂 Filters can be defined using a file.
- 🛑 Silent mode for suppressing error output.

## Installation 🛠️

To install TLSpider, you can use the `go install` command:

```sh
go install github.com/SecWithMoh/tlspider@latest
```

## Usage 🚀

### Help Menu

```
Usage of tlspider:
  -output string
        Output format: csv or json (default "json")
  -filter string
        File with list of domains for filtering
  -crtsh
        Integrate with CRT.SH to extract more subdomains
  -raw
        Output only the extracted domains (hosts)
  -port string
        Ports to scan (comma-separated, default "443")
  -silent
        Run in silent mode
  -v, -verbose
        Run in verbose mode
```

### Examples

#### Extract SANs from a Single Host

```sh
tlspider -u example.com -output json
```

#### Extract SANs from Multiple Hosts in a File

```sh
tlspider -hosts hosts.txt -output csv
```

#### Pipe Hosts from Stdin and Sort Unique Results

```sh
echo "example.com" | tlspider -output csv | sort -u
```

#### Silent Mode

```sh
tlspider -u example.com -silent
```

#### Verbose Mode

```sh
tlspider -u example.com -v
```

#### Specifying Ports

```sh
tlspider -u example.com -port 443,8443
```

## License 📜

This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See the [LICENSE](LICENSE) file for more details.

## Contributing 🤝

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Support 💬

If you have any questions or need support, please [open an issue](https://github.com/SecWithMoh/tlspider/issues).

---

Follow me on Twitter: [@secwithmoh](https://twitter.com/secwithmoh) 🐦
