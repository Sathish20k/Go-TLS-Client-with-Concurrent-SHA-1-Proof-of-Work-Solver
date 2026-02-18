package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- USER DETAILS ---
const (
	MY_NAME      = "SATHISH KARTHIKEYAN"
	MY_MAIL1     = "ksathish2003k@gmail.com"
	MY_SKYPE     = ""
	MY_BIRTHDATE = ""
	MY_COUNTRY   = "India"
	ADDR_LINE1   = "tnagar"
	ADDR_LINE2   = "chennai, 600017"
)

func getSHA1(data string) string {
	h := sha1.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func isMatch(hash []byte, difficulty int) bool {
	fullBytes := difficulty / 2
	for i := 0; i < fullBytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}
	if difficulty%2 != 0 {
		if (hash[fullBytes] >> 4) != 0 {
			return false
		}
	}
	return true
}

func solvePOW(authdata string, difficulty int) string {
	numCores := runtime.NumCPU()
	foundChan := make(chan string, 1)
	var done int32 = 0
	var wg sync.WaitGroup

	startTime := time.Now()
	fmt.Printf("[*] Solving POW Difficulty %d on %d cores...\n", difficulty, numCores)

	for i := 0; i < numCores; i++ {
		wg.Add(1)
		go func(start int) {
			defer wg.Done()
			h := sha1.New()
			prefix := []byte(authdata)
			for n := int64(start); atomic.LoadInt32(&done) == 0; n += int64(numCores) {
				suffixStr := strconv.FormatInt(n, 10)
				h.Reset()
				h.Write(prefix)
				h.Write([]byte(suffixStr))
				hashSum := h.Sum(nil)

				if isMatch(hashSum, difficulty) {
					if atomic.CompareAndSwapInt32(&done, 0, 1) {
						foundChan <- suffixStr
					}
					return
				}
			}
		}(i)
	}

	result := <-foundChan
	wg.Wait()
	fmt.Printf("[+] Suffix Found in %v\n", time.Since(startTime))
	return result
}

func main() {
	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		fmt.Printf("Fatal: Cert error: %v\n", err)
		return
	}

	caCert, _ := ioutil.ReadFile("ca.crt")
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", "18.202.148.130:3336", tlsConfig)
	if err != nil {
		fmt.Printf("Connection Failed: %v\n", err)
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	var authdata string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		args := strings.Fields(line)
		if len(args) == 0 {
			continue
		}

		cmd := args[0]
		fmt.Printf("← %s\n", line)

		switch cmd {
		case "HELO":
			fmt.Fprint(conn, "EHLO\n")
		case "POW":
			authdata = args[1]
			diff, _ := strconv.Atoi(args[2])
			suffix := solvePOW(authdata, diff)
			fmt.Fprintf(conn, "%s\n", suffix)
		case "NAME":
			fmt.Fprintf(conn, "%s %s\n", getSHA1(authdata+args[1]), MY_NAME)
		case "MAILNUM":
			fmt.Fprintf(conn, "%s 1\n", getSHA1(authdata+args[1]))
		case "MAIL1":
			fmt.Fprintf(conn, "%s %s\n", getSHA1(authdata+args[1]), MY_MAIL1)
		case "SKYPE":
			fmt.Fprintf(conn, "%s %s\n", getSHA1(authdata+args[1]), MY_SKYPE)
		case "BIRTHDATE":
			fmt.Fprintf(conn, "%s %s\n", getSHA1(authdata+args[1]), MY_BIRTHDATE)
		case "COUNTRY":
			fmt.Fprintf(conn, "%s %s\n", getSHA1(authdata+args[1]), MY_COUNTRY)
		case "ADDRNUM":
			fmt.Fprintf(conn, "%s 2\n", getSHA1(authdata+args[1]))
		case "ADDRLINE1":
			fmt.Fprintf(conn, "%s %s\n", getSHA1(authdata+args[1]), ADDR_LINE1)
		case "ADDRLINE2":
			fmt.Fprintf(conn, "%s %s\n", getSHA1(authdata+args[1]), ADDR_LINE2)
		case "END":
			fmt.Fprint(conn, "OK\n")
			fmt.Println("[SUCCESS] Finished.")
			return
		case "ERROR":
			fmt.Println("Error:", line)
			return
		}
	}
}
