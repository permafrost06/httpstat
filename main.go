package main

import (
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

const (
	httpsTemplate = `` +
		`  DNS Lookup   TCP Connection   TLS Handshake   Server Processing   Content Transfer` + "\n" +
		`[%s  |     %s  |    %s  |        %s  |       %s  ]` + "\n" +
		`            |                |               |                   |                  |` + "\n" +
		`   namelookup:%s      |               |                   |                  |` + "\n" +
		`                       connect:%s     |                   |                  |` + "\n" +
		`                                   pretransfer:%s         |                  |` + "\n" +
		`                                                     starttransfer:%s        |` + "\n" +
		`                                                                                total:%s` + "\n"

	httpTemplate = `` +
		`   DNS Lookup   TCP Connection   Server Processing   Content Transfer` + "\n" +
		`[ %s  |     %s  |        %s  |       %s  ]` + "\n" +
		`             |                |                   |                  |` + "\n" +
		`    namelookup:%s      |                   |                  |` + "\n" +
		`                        connect:%s         |                  |` + "\n" +
		`                                      starttransfer:%s        |` + "\n" +
		`                                                                 total:%s` + "\n"

	httpsTextTemplate = `` +
		`DNS Lookup: %dms` + "\n" +
		`namelookup: %dms` + "\n" +
		`TCP Connection: %dms` + "\n" +
		`connect: %dms` + "\n" +
		`TLS Handshake: %dms` + "\n" +
		`pretransfer: %dms` + "\n" +
		`Server Processing: %dms` + "\n" +
		`starttransfer: %dms` + "\n" +
		`Content Transfer: %dms` + "\n" +
		`Total: %dms` + "\n\n"

	httpTextTemplate = `` +
		`DNS Lookup: %dms` + "\n" +
		`namelookup: %dms` + "\n" +
		`TCP Connection: %dms` + "\n" +
		`connect: %dms` + "\n" +
		`Server Processing: %dms` + "\n" +
		`starttransfer: %dms` + "\n" +
		`Content Transfer: %dms` + "\n" +
		`Total: %dms` + "\n\n"
)

var (
	// Command line flags.
	httpMethod        string
	postBody          string
	followRedirects   bool
	onlyHeader        bool
	insecure          bool
	httpHeaders       headers
	saveOutput        bool
	outputFile        string
	showVersion       bool
	clientCertFile    string
	fourOnly          bool
	sixOnly           bool
	iterations        int
	hideSingleResults bool
	showTextResults   bool
	resultsOnly       bool
	csvFile           string

	// number of redirects followed
	redirectsFollowed int

	version = "devel" // for -v flag, updated during the release process with -ldflags=-X=main.version=...
)

const maxRedirects = 10

func init() {
	flag.StringVar(&httpMethod, "X", "GET", "HTTP method to use")
	flag.StringVar(&postBody, "d", "", "the body of a POST or PUT request; from file use @filename")
	flag.BoolVar(&followRedirects, "L", false, "follow 30x redirects")
	flag.BoolVar(&onlyHeader, "I", false, "don't read body of request")
	flag.BoolVar(&insecure, "k", false, "allow insecure SSL connections")
	flag.Var(&httpHeaders, "H", "set HTTP header; repeatable: -H 'Accept: ...' -H 'Range: ...'")
	flag.BoolVar(&saveOutput, "O", false, "save body as remote filename")
	flag.StringVar(&outputFile, "o", "", "output file for body")
	flag.BoolVar(&showVersion, "v", false, "print version number")
	flag.StringVar(&clientCertFile, "E", "", "client cert file for tls config")
	flag.BoolVar(&fourOnly, "4", false, "resolve IPv4 addresses only")
	flag.BoolVar(&sixOnly, "6", false, "resolve IPv6 addresses only")
	flag.IntVar(&iterations, "n", 1, "Number of iterations")
	flag.BoolVar(&hideSingleResults, "q", false, "Hide single results, only show average and highest")
	flag.BoolVar(&showTextResults, "t", false, "Show text results, default is graphical")
	flag.BoolVar(&resultsOnly, "qh", false, "Only show results")
	flag.StringVar(&csvFile, "w", "", "save results in a csv file")

	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] URL\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "ENVIRONMENT:")
	fmt.Fprintln(os.Stderr, "  HTTP_PROXY    proxy for HTTP requests; complete URL or HOST[:PORT]")
	fmt.Fprintln(os.Stderr, "                used for HTTPS requests if HTTPS_PROXY undefined")
	fmt.Fprintln(os.Stderr, "  HTTPS_PROXY   proxy for HTTPS requests; complete URL or HOST[:PORT]")
	fmt.Fprintln(os.Stderr, "  NO_PROXY      comma-separated list of hosts to exclude from proxy")
}

func printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(color.Output, format, a...)
}

func grayscale(code color.Attribute) func(string, ...interface{}) string {
	return color.New(code + 232).SprintfFunc()
}

func calculateVariance(data []float64) float64 {
	n := len(data)
	if n <= 1 {
		return 0.0 // Variance is undefined for n <= 1
	}

	// Calculate the mean
	var sum float64
	for _, value := range data {
		sum += value
	}
	mean := sum / float64(n)

	// Calculate the squared differences from the mean
	var squaredDiffSum float64
	for _, value := range data {
		diff := value - mean
		squaredDiffSum += diff * diff
	}

	// Calculate the sample variance using Bessel's correction
	variance := squaredDiffSum / float64(n-1)
	return variance
}

func calculateStandardDeviation(data []float64) float64 {
	variance := calculateVariance(data) // Reuse the variance calculation function
	standardDeviation := math.Sqrt(variance)
	return standardDeviation
}

type Result struct {
	dns_lookup        int
	tcp_connection    int
	tls_handshake     int
	server_processing int
	content_transfer  int
	namelookup        int
	connect           int
	pretransfer       int
	starttransfer     int
	total             int
}

func colorize(s string) string {
	v := strings.Split(s, "\n")
	v[0] = grayscale(16)(v[0])
	return strings.Join(v, "\n")
}

func fmta(d int) string {
	return color.CyanString("%7dms", d)
}

func fmtb(d int) string {
	return color.CyanString("%-9s", strconv.Itoa(d)+"ms")
}

func main() {
	flag.Parse()

	if showVersion {
		fmt.Printf("%s %s (runtime: %s)\n", os.Args[0], version, runtime.Version())
		os.Exit(0)
	}

	if fourOnly && sixOnly {
		fmt.Fprintf(os.Stderr, "%s: Only one of -4 and -6 may be specified\n", os.Args[0])
		os.Exit(-1)
	}

	args := flag.Args()
	if len(args) != 1 {
		flag.Usage()
		os.Exit(2)
	}

	if (httpMethod == "POST" || httpMethod == "PUT") && postBody == "" {
		log.Fatal("must supply post body using -d when POST or PUT is used")
	}

	if onlyHeader {
		httpMethod = "HEAD"
	}

	url := parseURL(args[0])

	var times []Result

	for i := 0; i < iterations; i++ {
		if i > 0 && hideSingleResults {
			printf("\u001b[1F")
		}

		if iterations > 1 {
			printf("Running benchmark %d of %d\n", i+1, iterations)
		}

		result, err := visit(url, hideSingleResults)

		if err != nil {
			return
		}

		times = append(times, result)
	}

	if iterations <= 1 {
		return
	}

	printBenchmarkResults(times)

	if csvFile != "" {
		saveToFile(times)
	}
}

func getAvgAndHighest(times []Result) (avg Result, highest Result, tracker Result) {
	total := Result{}

	for i, res := range times {
		total.dns_lookup += res.dns_lookup
		total.tcp_connection += res.tcp_connection
		total.tls_handshake += res.tls_handshake
		total.server_processing += res.server_processing
		total.content_transfer += res.content_transfer
		total.namelookup += res.namelookup
		total.connect += res.connect
		total.pretransfer += res.pretransfer
		total.starttransfer += res.starttransfer
		total.total += res.total

		if res.dns_lookup > highest.dns_lookup {
			highest.dns_lookup = res.dns_lookup
			tracker.dns_lookup = i
		}
		if res.tcp_connection > highest.tcp_connection {
			highest.tcp_connection = res.tcp_connection
			tracker.tcp_connection = i
		}
		if res.tls_handshake > highest.tls_handshake {
			highest.tls_handshake = res.tls_handshake
			tracker.tls_handshake = i
		}
		if res.server_processing > highest.server_processing {
			highest.server_processing = res.server_processing
			tracker.server_processing = i
		}
		if res.content_transfer > highest.content_transfer {
			highest.content_transfer = res.content_transfer
			tracker.content_transfer = i
		}
		if res.namelookup > highest.namelookup {
			highest.namelookup = res.namelookup
			tracker.namelookup = i
		}
		if res.connect > highest.connect {
			highest.connect = res.connect
			tracker.connect = i
		}
		if res.pretransfer > highest.pretransfer {
			highest.pretransfer = res.pretransfer
			tracker.pretransfer = i
		}
		if res.starttransfer > highest.starttransfer {
			highest.starttransfer = res.starttransfer
			tracker.starttransfer = i
		}
		if res.total > highest.total {
			highest.total = res.total
			tracker.total = i
		}
	}

	avg = Result{
		total.dns_lookup / iterations,
		total.tcp_connection / iterations,
		total.tls_handshake / iterations,
		total.server_processing / iterations,
		total.content_transfer / iterations,
		total.namelookup / iterations,
		total.connect / iterations,
		total.pretransfer / iterations,
		total.starttransfer / iterations,
		total.total / iterations,
	}

	return avg, highest, tracker
}

func printBenchmarkResults(times []Result) {
	avg, highest, tracker := getAvgAndHighest(times)
	https := highest.tls_handshake != 0

	const httpsBenchmarkResultTemplate = `Benchmark stats:
                   Average   Maximum
DNS Lookup:         %4dms    %4dms (on run %d)
namelookup:         %4dms    %4dms (on run %d)
TCP Connection:     %4dms    %4dms (on run %d)
connect:            %4dms    %4dms (on run %d)
TLS Handshake:      %4dms    %4dms (on run %d)
pretransfer:        %4dms    %4dms (on run %d)
Server Processing:  %4dms    %4dms (on run %d)
starttransfer:      %4dms    %4dms (on run %d)
Content Transfer:   %4dms    %4dms (on run %d)
Total:              %4dms    %4dms (on run %d)
`

	const httpBenchmarkResultTemplate = `Benchmark stats:
                   Average   Maximum
DNS Lookup:         %4dms    %4dms (on run %d)
namelookup:         %4dms    %4dms (on run %d)
TCP Connection:     %4dms    %4dms (on run %d)
connect:            %4dms    %4dms (on run %d)
Server Processing:  %4dms    %4dms (on run %d)
starttransfer:      %4dms    %4dms (on run %d)
Content Transfer:   %4dms    %4dms (on run %d)
Total:              %4dms    %4dms (on run %d)
`

	if https {
		printf(httpsBenchmarkResultTemplate,
			avg.dns_lookup, highest.dns_lookup, tracker.dns_lookup,
			avg.namelookup, highest.namelookup, tracker.namelookup,
			avg.tcp_connection, highest.tcp_connection, tracker.tcp_connection,
			avg.connect, highest.connect, tracker.connect,
			avg.tls_handshake, highest.tls_handshake, tracker.tls_handshake,
			avg.pretransfer, highest.pretransfer, tracker.pretransfer,
			avg.server_processing, highest.server_processing, tracker.server_processing,
			avg.starttransfer, highest.starttransfer, tracker.starttransfer,
			avg.content_transfer, highest.content_transfer, tracker.content_transfer,
			avg.total, highest.total, tracker.total,
		)
	} else {
		printf(httpBenchmarkResultTemplate,
			avg.dns_lookup, highest.dns_lookup, tracker.dns_lookup,
			avg.namelookup, highest.namelookup, tracker.namelookup,
			avg.tcp_connection, highest.tcp_connection, tracker.tcp_connection,
			avg.connect, highest.connect, tracker.connect,
			avg.server_processing, highest.server_processing, tracker.server_processing,
			avg.starttransfer, highest.starttransfer, tracker.starttransfer,
			avg.content_transfer, highest.content_transfer, tracker.content_transfer,
			avg.total, highest.total, tracker.total,
		)
	}

	printVarianceAndDeviation(times)
}

func printVarianceAndDeviation(times []Result) {
	totals := make([]float64, iterations)
	for i, time := range times {
		totals[i] = float64(time.total)
	}

	printf("Variance of total times: %.2f\n", calculateVariance(totals))
	printf("Standard deviation of total times: %.2f\n", calculateStandardDeviation(totals))
}

func saveToFile(results []Result) {
	fp, err := os.Create(csvFile)

	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	csvWriter := csv.NewWriter(fp)

	data := [][]string{{"DNS Lookup", "TCP Connection", "TLS Handshake", "Server Processing", "Content Transfer", "namelookup", "connect", "pretransfer", "starttransfer", "total"}}
	for _, result := range results {
		row := []string{strconv.Itoa(result.dns_lookup), strconv.Itoa(result.tcp_connection), strconv.Itoa(result.tls_handshake),
			strconv.Itoa(result.server_processing), strconv.Itoa(result.content_transfer), strconv.Itoa(result.namelookup),
			strconv.Itoa(result.connect), strconv.Itoa(result.pretransfer), strconv.Itoa(result.starttransfer), strconv.Itoa(result.total)}
		data = append(data, row)
	}

	csvWriter.WriteAll(data)
	csvWriter.Flush()

	fp.Close()
}

func printResult(res Result) {
	https := res.tls_handshake != 0

	if https && showTextResults {
		printf(httpsTextTemplate,
			res.dns_lookup,
			res.tcp_connection,
			res.tls_handshake,
			res.server_processing,
			res.content_transfer,
			res.namelookup,
			res.connect,
			res.pretransfer,
			res.starttransfer,
			res.total,
		)
		return
	}

	if !https && showTextResults {
		printf(httpTextTemplate,
			res.dns_lookup,
			res.tcp_connection,
			res.server_processing,
			res.content_transfer,
			res.namelookup,
			res.connect,
			res.starttransfer,
			res.total,
		)
		return
	}

	if https {
		printf(colorize(httpsTemplate),
			fmta(res.dns_lookup),
			fmta(res.tcp_connection),
			fmta(res.tls_handshake),
			fmta(res.server_processing),
			fmta(res.content_transfer),
			fmtb(res.namelookup),
			fmtb(res.connect),
			fmtb(res.pretransfer),
			fmtb(res.starttransfer),
			fmtb(res.total),
		)
		return
	}

	printf(colorize(httpTemplate),
		fmta(res.dns_lookup),
		fmta(res.tcp_connection),
		fmta(res.server_processing),
		fmta(res.content_transfer),
		fmtb(res.namelookup),
		fmtb(res.connect),
		fmtb(res.starttransfer),
		fmtb(res.total),
	)
}

// readClientCert - helper function to read client certificate
// from pem formatted file
func readClientCert(filename string) []tls.Certificate {
	if filename == "" {
		return nil
	}
	var (
		pkeyPem []byte
		certPem []byte
	)

	// read client certificate file (must include client private key and certificate)
	certFileBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("failed to read client certificate file: %v", err)
	}

	for {
		block, rest := pem.Decode(certFileBytes)
		if block == nil {
			break
		}
		certFileBytes = rest

		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			pkeyPem = pem.EncodeToMemory(block)
		}
		if strings.HasSuffix(block.Type, "CERTIFICATE") {
			certPem = pem.EncodeToMemory(block)
		}
	}

	cert, err := tls.X509KeyPair(certPem, pkeyPem)
	if err != nil {
		log.Fatalf("unable to load client cert and key pair: %v", err)
	}
	return []tls.Certificate{cert}
}

func parseURL(uri string) *url.URL {
	if !strings.Contains(uri, "://") && !strings.HasPrefix(uri, "//") {
		uri = "//" + uri
	}

	url, err := url.Parse(uri)
	if err != nil {
		log.Fatalf("could not parse url %q: %v", uri, err)
	}

	if url.Scheme == "" {
		url.Scheme = "http"
		if !strings.HasSuffix(url.Host, ":80") {
			url.Scheme += "s"
		}
	}
	return url
}

func headerKeyValue(h string) (string, string) {
	i := strings.Index(h, ":")
	if i == -1 {
		log.Fatalf("Header '%s' has invalid format, missing ':'", h)
	}
	return strings.TrimRight(h[:i], " "), strings.TrimLeft(h[i:], " :")
}

func dialContext(network string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		return (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: false,
		}).DialContext(ctx, network, addr)
	}
}

// visit visits a url and times the interaction.
// If the response is a 30x, visit follows the redirect.
func visit(url *url.URL, hideResult bool) (Result, error) {
	req := newRequest(httpMethod, url, postBody)

	var t0, t1, t2, t3, t4, t5, t6 time.Time

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { t0 = time.Now() },
		DNSDone:  func(_ httptrace.DNSDoneInfo) { t1 = time.Now() },
		ConnectStart: func(_, _ string) {
			if t1.IsZero() {
				// connecting to IP
				t1 = time.Now()
			}
		},
		ConnectDone: func(net, addr string, err error) {
			if err != nil {
				log.Fatalf("unable to connect to host %v: %v", addr, err)
			}
			t2 = time.Now()

			if !hideResult && !resultsOnly {
				printf("\n%s%s\n", color.GreenString("Connected to "), color.CyanString(addr))
			}
		},
		GotConn:              func(_ httptrace.GotConnInfo) { t3 = time.Now() },
		GotFirstResponseByte: func() { t4 = time.Now() },
		TLSHandshakeStart:    func() { t5 = time.Now() },
		TLSHandshakeDone:     func(_ tls.ConnectionState, _ error) { t6 = time.Now() },
	}
	req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))

	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	switch {
	case fourOnly:
		tr.DialContext = dialContext("tcp4")
	case sixOnly:
		tr.DialContext = dialContext("tcp6")
	}

	switch url.Scheme {
	case "https":
		host, _, err := net.SplitHostPort(req.Host)
		if err != nil {
			host = req.Host
		}

		tr.TLSClientConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: insecure,
			Certificates:       readClientCert(clientCertFile),
			MinVersion:         tls.VersionTLS12,
		}
	}

	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// always refuse to follow redirects, visit does that
			// manually if required.
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("failed to read response: %v", err)
	}

	// Print SSL/TLS version which is used for connection
	connectedVia := "plaintext"
	if resp.TLS != nil {
		switch resp.TLS.Version {
		case tls.VersionTLS12:
			connectedVia = "TLSv1.2"
		case tls.VersionTLS13:
			connectedVia = "TLSv1.3"
		}
	}

	bodyMsg := readResponseBody(req, resp)
	resp.Body.Close()

	t7 := time.Now() // after read body
	if t0.IsZero() {
		// we skipped DNS
		t0 = t1
	}

	result := Result{
		int(t1.Sub(t0) / time.Millisecond),
		int(t2.Sub(t1) / time.Millisecond),
		0,
		int(t4.Sub(t3) / time.Millisecond),
		int(t7.Sub(t4) / time.Millisecond),
		int(t1.Sub(t0) / time.Millisecond),
		int(t2.Sub(t0) / time.Millisecond),
		0,
		int(t4.Sub(t0) / time.Millisecond),
		int(t7.Sub(t0) / time.Millisecond),
	}

	if url.Scheme == "https" {
		result.tls_handshake = int(t6.Sub(t5) / time.Millisecond)
		result.pretransfer = int(t3.Sub(t0) / time.Millisecond)
	}

	if !hideResult {
		if !resultsOnly {
			printf("\n%s %s\n", color.GreenString("Connected via"), color.CyanString("%s", connectedVia))

			// print status line and headers
			printf("\n%s%s%s\n", color.GreenString("HTTP"), grayscale(14)("/"), color.CyanString("%d.%d %s", resp.ProtoMajor, resp.ProtoMinor, resp.Status))

			names := make([]string, 0, len(resp.Header))
			for k := range resp.Header {
				names = append(names, k)
			}
			sort.Sort(headers(names))
			for _, k := range names {
				printf("%s %s\n", grayscale(14)(k+":"), color.CyanString(strings.Join(resp.Header[k], ",")))
			}

			if bodyMsg != "" {
				printf("\n%s\n", bodyMsg)
			}

			fmt.Println()
		}

		printResult(result)
	}

	if followRedirects && isRedirect(resp) {
		loc, err := resp.Location()
		if err != nil {
			if err == http.ErrNoLocation {
				// 30x but no Location to follow, give up.
				return Result{}, errors.New("30x but no Location to follow")
			}
			log.Fatalf("unable to follow redirect: %v", err)
		}

		redirectsFollowed++
		if redirectsFollowed > maxRedirects {
			log.Fatalf("maximum number of redirects (%d) followed", maxRedirects)
		}

		visit(loc, hideSingleResults)
	}
	return result, nil
}

func isRedirect(resp *http.Response) bool {
	return resp.StatusCode > 299 && resp.StatusCode < 400
}

func newRequest(method string, url *url.URL, body string) *http.Request {
	req, err := http.NewRequest(method, url.String(), createBody(body))
	if err != nil {
		log.Fatalf("unable to create request: %v", err)
	}
	for _, h := range httpHeaders {
		k, v := headerKeyValue(h)
		if strings.EqualFold(k, "host") {
			req.Host = v
			continue
		}
		req.Header.Add(k, v)
	}
	return req
}

func createBody(body string) io.Reader {
	if strings.HasPrefix(body, "@") {
		filename := body[1:]
		f, err := os.Open(filename)
		if err != nil {
			log.Fatalf("failed to open data file %s: %v", filename, err)
		}
		return f
	}
	return strings.NewReader(body)
}

// getFilenameFromHeaders tries to automatically determine the output filename,
// when saving to disk, based on the Content-Disposition header.
// If the header is not present, or it does not contain enough information to
// determine which filename to use, this function returns "".
func getFilenameFromHeaders(headers http.Header) string {
	// if the Content-Disposition header is set parse it
	if hdr := headers.Get("Content-Disposition"); hdr != "" {
		// pull the media type, and subsequent params, from
		// the body of the header field
		mt, params, err := mime.ParseMediaType(hdr)

		// if there was no error and the media type is attachment
		if err == nil && mt == "attachment" {
			if filename := params["filename"]; filename != "" {
				return filename
			}
		}
	}

	// return an empty string if we were unable to determine the filename
	return ""
}

// readResponseBody consumes the body of the response.
// readResponseBody returns an informational message about the
// disposition of the response body's contents.
func readResponseBody(req *http.Request, resp *http.Response) string {
	if isRedirect(resp) || req.Method == http.MethodHead {
		return ""
	}

	w := io.Discard
	msg := color.CyanString("Body discarded")

	if saveOutput || outputFile != "" {
		filename := outputFile

		if saveOutput {
			// try to get the filename from the Content-Disposition header
			// otherwise fall back to the RequestURI
			if filename = getFilenameFromHeaders(resp.Header); filename == "" {
				filename = path.Base(req.URL.RequestURI())
			}

			if filename == "/" {
				log.Fatalf("No remote filename; specify output filename with -o to save response body")
			}
		}

		f, err := os.Create(filename)
		if err != nil {
			log.Fatalf("unable to create file %s: %v", filename, err)
		}
		defer f.Close()
		w = f
		msg = color.CyanString("Body read")
	}

	if _, err := io.Copy(w, resp.Body); err != nil && w != io.Discard {
		log.Fatalf("failed to read response body: %v", err)
	}

	return msg
}

type headers []string

func (h headers) String() string {
	var o []string
	for _, v := range h {
		o = append(o, "-H "+v)
	}
	return strings.Join(o, " ")
}

func (h *headers) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func (h headers) Len() int      { return len(h) }
func (h headers) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h headers) Less(i, j int) bool {
	a, b := h[i], h[j]

	// server always sorts at the top
	if a == "Server" {
		return true
	}
	if b == "Server" {
		return false
	}

	endtoend := func(n string) bool {
		// https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
		switch n {
		case "Connection",
			"Keep-Alive",
			"Proxy-Authenticate",
			"Proxy-Authorization",
			"TE",
			"Trailers",
			"Transfer-Encoding",
			"Upgrade":
			return false
		default:
			return true
		}
	}

	x, y := endtoend(a), endtoend(b)
	if x == y {
		// both are of the same class
		return a < b
	}
	return x
}
