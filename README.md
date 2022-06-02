# FollinaScanner
This is a tool written in Go that scans directories & files for the Follina exploit (CVE-2022-30190)

## Compiling
```sh
git clone https://github.com/ErrorNoInternet/FollinaScanner
cd FollinaScanner
go build
```

## Running
```sh
# Scan the current directory
./follina-scanner -R .

# Scan a specific file
./follina-scanner amogus.docx
```
Use `./follina-scanner --help` for a list of arguments

