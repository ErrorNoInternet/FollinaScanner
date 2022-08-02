# FollinaScanner
A tool written in Go that scans files & directories for the Follina exploit (CVE-2022-30190)
![Screenshot](https://raw.githubusercontent.com/ErrorNoInternet/FollinaScanner/main/screenshots/screenshot0.png)
*(Note: "Suspicious files" means files that have a URL in them but isn't working)*

## Compiling
```
git clone https://github.com/ErrorNoInternet/FollinaScanner
cd FollinaScanner
go build
```

## Usage
```
# Scan the current directory
./follina-scanner -r .

# Scan a specific file
./follina-scanner amogus.docx
```
Use `./follina-scanner --help` for a list of arguments

<sub>If you would like to modify or use this repository (including its code) in your own project, please be sure to credit!</sub>
