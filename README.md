# TLSpider 🕷️

TLSpider is a tool written in Go for extracting Subject Alternative Names (SANs) found in SSL Certificates directly from HTTPS websites. It provides automation for gathering DNS names (subdomains) and virtual servers from SSL certificates.

## Features

- Extracts SANs from SSL certificates of HTTPS websites.
- Supports output in CSV or JSON formats for easy integration with other tools.
- Filters out domain names that don't match the specified domain.
- Integrates with CRT.SH to extract additional subdomains from the same entity's certificates.
- Works with both publicly trusted certificates and self-signed certificates.

## Installation

To install TLSpider, you can use the `go install` command:

```sh
go install github.com/SecWithMoh/tlspider@latest
```

## Usage

### Extract SANs from a Single Host

```sh
tlspider -u example.com -output json
```

### Extract SANs from Multiple Hosts in a File

```sh
tlspider -hosts hosts.txt -output csv
```

### Pipe Hosts from Stdin and Sort Unique Results

```sh
echo "example.com" | tlspider -output csv | sort -u
```

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See the [LICENSE](LICENSE) file for more details.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Support

If you have any questions or need support, please [open an issue](https://github.com/SecWithMoh/tlspider/issues).

## Follow Me

Follow me on Twitter: [@secwithmoh](https://twitter.com/secwithmoh)

---
