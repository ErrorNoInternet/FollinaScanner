package main

import (
	"archive/zip"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	version           string = "1.0.1"
	recursiveScanning bool
	verboseOutput     bool
	scanned           int
	valid             int
	infectedFiles     []string
	suspiciousFiles   []string
	warningColor      *color.Color = color.New(color.FgRed)
)

func main() {
	helpPage := "(" + version + ") Usage: follina-scanner [OPTION]... [FILE]...\n\n" +
		"\t-r, --recursive\t\tRecursively scan files in a directory\n" +
		"\t-v, --verbose\t\tDisplay everything that's happening"
	if len(os.Args) > 1 {
		for index, argument := range os.Args {
			if index == 0 {
				continue
			}
			if argument == "-h" || argument == "--help" {
				fmt.Println(helpPage)
				return
			} else if argument == "-r" || argument == "--recursive" {
				recursiveScanning = true
			} else if argument == "-v" || argument == "--verbose" {
				verboseOutput = true
			} else {
				fileData, err := os.Stat(argument)
				if err != nil {
					fmt.Printf("[%v] %v\n", argument, err.Error())
					continue
				}
				if fileData.IsDir() {
					if recursiveScanning {
						err = filepath.Walk(argument,
							func(path string, data os.FileInfo, err error) error {
								if err != nil {
									return err
								}
								fileData, err := os.Stat(path)
								if err == nil {
									if !fileData.IsDir() {
										scanFile(path)
										scanned++
									}
									return nil
								} else {
									fmt.Printf("[%v] %v\n", argument, err.Error())
									return err
								}
							})
						if err != nil {
							fmt.Printf("[%v] %v\n", argument, err.Error())
						}
					} else {
						fmt.Printf("[%v] Is a directory: %v\n", argument, argument)
					}
				} else {
					scanFile(argument)
					scanned++
				}
			}
		}
		if scanned > 0 {
			fmt.Println()
		}
		fmt.Printf(
			color.New(color.FgGreen).Add(color.Bold).Sprintf("Scanned files: ") + strconv.Itoa(scanned) +
				color.New(color.FgGreen).Add(color.Bold).Sprintf("\nValid documents: ") + strconv.Itoa(valid) +
				color.New(color.FgYellow).Add(color.Bold).Sprintf("\nSuspicious files (%v): ", len(suspiciousFiles)) + strings.Join(suspiciousFiles, ", ") +
				color.New(color.FgRed).Add(color.Bold).Sprintf("\nInfected files (%v): ", len(infectedFiles)) + strings.Join(infectedFiles, ", ") + "\n",
		)
	} else {
		fmt.Println(helpPage)
	}
}

func scanFile(filePath string) {
	document, err := zip.OpenReader(filePath)
	if err != nil {
		if verboseOutput {
			fmt.Printf("[%v] %v\n", filePath, err.Error())
		}
		return
	}
	fmt.Printf("[%v] Scanning file as zip...\n", filePath)
	valid++
	defer document.Close()
	for _, zipFile := range document.File {
		if strings.Contains(zipFile.Name, "_rels") && !zipFile.FileInfo().IsDir() {
			if verboseOutput {
				fmt.Printf("[%v] Found %v\n", filePath, zipFile.Name)
			}
			file, err := zipFile.Open()
			if err != nil {
				fmt.Printf("[%v] %v\n", filePath, err.Error())
				continue
			}
			defer file.Close()
			fileBytes, err := ioutil.ReadAll(file)
			if err != nil {
				fmt.Printf("[%v] %v\n", filePath, err.Error())
				continue
			}
			if len(strings.TrimSpace(string(fileBytes))) == 0 {
				if verboseOutput {
					fmt.Printf("[%v] Empty file: %v\n", filePath, zipFile.Name)
				}
				continue
			}
			regex := regexp.MustCompile("Target=\"(mhtml:|x-usc:)?https?://.+\\.html.?\"")
			matches := regex.FindAll(fileBytes, 1)
			if len(matches) == 0 {
				if verboseOutput {
					fmt.Printf("[%v] No URL found in %v\n", filePath, zipFile.Name)
				}
				continue
			}
			match := strings.Replace(string(matches[0]), "mhtml:", "", -1)
			url := strings.Split(match[8:len(match)-1], "!")[0]
			fmt.Printf("[%v] Found URL in %v: \"%v\"\n", filePath, zipFile.Name, url)
			if verboseOutput {
				fmt.Printf("[%v] Sending HTTP GET request to %v...\n", filePath, url)
			}
			client := &http.Client{Timeout: 10 * time.Second}
			responseObject, err := client.Get(url)
			if err != nil {
				warningColor.Printf("[%v] %v\n", filePath, err.Error())
				suspiciousFiles = append(suspiciousFiles, filePath)
				continue
			}
			if verboseOutput {
				fmt.Printf("[%v] Response received!\n", filePath)
			}
			responseBytes, err := ioutil.ReadAll(responseObject.Body)
			if err != nil {
				fmt.Printf("[%v] %v\n", filePath, err.Error())
				suspiciousFiles = append(suspiciousFiles, filePath)
				continue
			}
			if strings.Contains(string(responseBytes), "ms-msdt") {
				message := fmt.Sprintf("[%v] Found Follina exploit in %v (%v)", filePath, filePath, url)
				separator := strings.Repeat("=", len(message))
				warningColor.Printf("%v\n%v\n%v\n", separator, message, separator)
				infectedFiles = append(infectedFiles, filePath)
			} else {
				fmt.Printf("[%v] No Follina exploit found\n", filePath)
			}
			return
		}
	}
}
