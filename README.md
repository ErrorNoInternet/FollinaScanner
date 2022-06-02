# FollinaScanner
A tool written in Go that scans files & directories for the Follina exploit (CVE-2022-30190)
![Screenshot](https://raw.githubusercontent.com/ErrorNoInternet/FollinaScanner/main/screenshots/screenshot0.png)
*(Note: "Suspicious files" means files that have a URL in them but isn't working)*

## Compiling
```sh
git clone https://github.com/ErrorNoInternet/FollinaScanner
cd FollinaScanner
go build
```

## Usage
```sh
# Scan the current directory
./follina-scanner -R .

# Scan a specific file
./follina-scanner amogus.docx
```
Use `./follina-scanner --help` for a list of arguments

