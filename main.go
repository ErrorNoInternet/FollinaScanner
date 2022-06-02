package main

import (
	"archive/zip"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

var (
	recursiveScanning bool
	verboseOutput     bool
	warningColor      *color.Color = color.New(color.FgRed)
)

func main() {
	helpPage := "Usage: follina-scanner [OPTION]... [FILE]...\n\n" +
		"\t-R, --recursive\t\tRecursively scan files in a directory\n" +
		"\t-v, --verbose\t\tDisplay everything that's happening"
	if len(os.Args) > 1 {
		for index, argument := range os.Args {
			if index == 0 {
				continue
			}
			if argument == "-h" || argument == "--help" {
				fmt.Println(helpPage)
				return
			} else if argument == "-R" || argument == "--recursive" {
				recursiveScanning = true
			} else if argument == "-v" || argument == "--verbose" {
				verboseOutput = true
			} else {
				fileData, errorObject := os.Stat(argument)
				if errorObject != nil {
					fmt.Println("[%v] %v\n", argument, errorObject.Error())
					continue
				}
				if fileData.IsDir() {
					if recursiveScanning {
						errorObject = filepath.Walk(argument,
							func(path string, data os.FileInfo, errorObject error) error {
								if errorObject != nil {
									return errorObject
								}
								fileData, errorObject := os.Stat(path)
								if errorObject == nil {
									if !fileData.IsDir() {
										scanFile(path)
									}
									return nil
								} else {
									fmt.Println("[%v] %v\n", argument, errorObject.Error())
									return errorObject
								}
							})
						if errorObject != nil {
							fmt.Println("[%v] %v\n", argument, errorObject.Error())
						}
					} else {
						fmt.Printf("[%v] Is a directory: %v\n", argument, argument)
					}
				} else {
					scanFile(argument)
				}
			}
		}
	} else {
		fmt.Println(helpPage)
	}
}

func scanFile(filePath string) {
	document, errorObject := zip.OpenReader(filePath)
	if errorObject != nil {
		fmt.Printf("[%v] %v\n", filePath, errorObject.Error())
		return
	}
	defer document.Close()
	for _, zipFile := range document.File {
		if zipFile.Name == "word/_rels/document.xml.rels" {
			if verboseOutput {
				fmt.Printf("[%v] Found word/_rels/document.xml.rels\n", filePath)
			}
			file, errorObject := zipFile.Open()
			if errorObject != nil {
				fmt.Printf("[%v] %v\n", filePath, errorObject.Error())
				return
			}
			defer file.Close()
			fileBytes, errorObject := ioutil.ReadAll(file)
			if errorObject != nil {
				fmt.Printf("[%v] %v\n", filePath, errorObject.Error())
				return
			}
			if len(strings.TrimSpace(string(fileBytes))) == 0 {
				if verboseOutput {
					fmt.Printf("[%v] Empty file: word/_rels/document.xml.rels\n", filePath)
				}
				return
			}
			regex := regexp.MustCompile("Target=\"https?://.+\\.html.?\"")
			matches := regex.FindAll(fileBytes, 1)
			if len(matches) == 0 {
				if verboseOutput {
					fmt.Printf("[%v] No URL found in word/_rels/document.xml.rels\n", filePath)
				}
				return
			}
			match := string(matches[0])
			url := strings.Trim(match[8:len(match)-1], "!")
			fmt.Printf("[%v] Found URL in word/_rels/document.xml.rels: \"%v\"\n", filePath, url)
			if verboseOutput {
				fmt.Printf("[%v] Sending HTTP GET request to %v...\n", filePath, url)
			}
			responseObject, errorObject := http.Get(url)
			if errorObject != nil {
				fmt.Printf("[%v] Unable to send a request: %v\n", filePath, errorObject.Error())
				return
			}
			if verboseOutput {
				fmt.Printf("[%v] Response received!\n", filePath)
			}
			responseBytes, errorObject := ioutil.ReadAll(responseObject.Body)
			if errorObject != nil {
				fmt.Printf("[%v] Unable to read request: %v\n", filePath, errorObject.Error())
				return
			}
			if strings.Contains(string(responseBytes), "ms-msdt") {
				message := fmt.Sprintf("[%v] Found Follina exploit in %v (%v)", filePath, filePath, url)
				separator := strings.Repeat("=", len(message))
				warningColor.Printf("%v\n%v\n%v\n", separator, message, separator)
			} else {
				fmt.Printf("[%v] No Follina exploit found in %v\n", filePath, filePath)
			}
			return
		}
	}
}
