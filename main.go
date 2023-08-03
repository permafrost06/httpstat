package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
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
)

var (
	// Command line flags.
	httpMethod      string
	postBody        string
	followRedirects bool
	onlyHeader      bool
	insecure        bool
	httpHeaders     headers
	saveOutput      bool
	outputFile      string
	showVersion     bool
	clientCertFile  string
	fourOnly        bool
	sixOnly         bool
	iterations      int

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
	flag.IntVar(&iterations, "i", 1, "Number of iterations")

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

type Result struct {
	dns_lookup        time.Duration
	tcp_connection    time.Duration
	tls_handshake     time.Duration
	server_processing time.Duration
	content_transfer  time.Duration
	namelookup        time.Duration
	connect           time.Duration
	pretransfer       time.Duration
	starttransfer     time.Duration
	total             time.Duration
}

type IntResult struct {
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
		result, err := visit(url)

		if err != nil {
			return
		}

		times = append(times, result)
	}

	if iterations > 1 {
		var total = Result{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		var highest = Result{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

		for _, res := range times {
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
			}
			if res.tcp_connection > highest.tcp_connection {
				highest.tcp_connection = res.tcp_connection
			}
			if res.tls_handshake > highest.tls_handshake {
				highest.tls_handshake = res.tls_handshake
			}
			if res.server_processing > highest.server_processing {
				highest.server_processing = res.server_processing
			}
			if res.content_transfer > highest.content_transfer {
				highest.content_transfer = res.content_transfer
			}
			if res.namelookup > highest.namelookup {
				highest.namelookup = res.namelookup
			}
			if res.connect > highest.connect {
				highest.connect = res.connect
			}
			if res.pretransfer > highest.pretransfer {
				highest.pretransfer = res.pretransfer
			}
			if res.starttransfer > highest.starttransfer {
				highest.starttransfer = res.starttransfer
			}
			if res.total > highest.total {
				highest.total = res.total
			}
		}

		var avg = IntResult{
			int(total.dns_lookup/time.Millisecond) / iterations,
			int(total.tcp_connection/time.Millisecond) / iterations,
			int(total.tls_handshake/time.Millisecond) / iterations,
			int(total.server_processing/time.Millisecond) / iterations,
			int(total.content_transfer/time.Millisecond) / iterations,
			int(total.namelookup/time.Millisecond) / iterations,
			int(total.connect/time.Millisecond) / iterations,
			int(total.pretransfer/time.Millisecond) / iterations,
			int(total.starttransfer/time.Millisecond) / iterations,
			int(total.total/time.Millisecond) / iterations,
		}

		printf("\nAveraged over %d iterations:\n\n", iterations)
		printIntResult(avg)

		printf("\nHighest in %d iterations:\n\n", iterations)
		printResult(highest)
	}
}

func printResult(res Result) {
	fmta := func(d time.Duration) string {
		return color.CyanString("%7dms", int(d/time.Millisecond))
	}

	fmtb := func(d time.Duration) string {
		return color.CyanString("%-9s", strconv.Itoa(int(d/time.Millisecond))+"ms")
	}

	colorize := func(s string) string {
		v := strings.Split(s, "\n")
		v[0] = grayscale(16)(v[0])
		return strings.Join(v, "\n")
	}

	if res.tls_handshake != 0 {
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

func printIntResult(res IntResult) {
	colorize := func(s string) string {
		v := strings.Split(s, "\n")
		v[0] = grayscale(16)(v[0])
		return strings.Join(v, "\n")
	}

	fmta := func(d int) string {
		return color.CyanString("%7dms", d)
	}

	fmtb := func(d int) string {
		return color.CyanString("%-9s", strconv.Itoa(d)+"ms")
	}

	if res.tls_handshake != 0 {
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
func visit(url *url.URL) (Result, error) {
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

			printf("\n%s%s\n", color.GreenString("Connected to "), color.CyanString(addr))
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
	printf("\n%s %s\n", color.GreenString("Connected via"), color.CyanString("%s", connectedVia))

	bodyMsg := readResponseBody(req, resp)
	resp.Body.Close()

	t7 := time.Now() // after read body
	if t0.IsZero() {
		// we skipped DNS
		t0 = t1
	}

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

	fmta := func(d time.Duration) string {
		return color.CyanString("%7dms", int(d/time.Millisecond))
	}

	fmtb := func(d time.Duration) string {
		return color.CyanString("%-9s", strconv.Itoa(int(d/time.Millisecond))+"ms")
	}

	colorize := func(s string) string {
		v := strings.Split(s, "\n")
		v[0] = grayscale(16)(v[0])
		return strings.Join(v, "\n")
	}

	fmt.Println()

	var (
		dns_lookup        = t1.Sub(t0)
		tcp_connection    = t2.Sub(t1)
		server_processing = t4.Sub(t3)
		content_transfer  = t7.Sub(t4)
		namelookup        = t1.Sub(t0)
		connect           = t2.Sub(t0)
		starttransfer     = t4.Sub(t0)
		total             = t7.Sub(t0)
	)

	var (
		tls_handshake time.Duration
		pretransfer   time.Duration
	)

	if url.Scheme == "https" {
		tls_handshake = t6.Sub(t5)
		pretransfer = t3.Sub(t0)
	}

	switch url.Scheme {
	case "https":
		printf(colorize(httpsTemplate),
			fmta(dns_lookup),
			fmta(tcp_connection),
			fmta(tls_handshake),
			fmta(server_processing),
			fmta(content_transfer),
			fmtb(namelookup),
			fmtb(connect),
			fmtb(pretransfer),
			fmtb(starttransfer),
			fmtb(total),
		)
	case "http":
		printf(colorize(httpTemplate),
			fmta(dns_lookup),
			fmta(tcp_connection),
			fmta(server_processing),
			fmta(content_transfer),
			fmtb(namelookup),
			fmtb(connect),
			fmtb(starttransfer),
			fmtb(total),
		)
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

		visit(loc)
	}
	return Result{
		dns_lookup, tcp_connection, tls_handshake, server_processing, content_transfer,
		namelookup, connect, pretransfer, starttransfer, total,
	}, nil
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
