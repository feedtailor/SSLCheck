package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	APP_NAME    = "sslcheck"
	APP_VERSION = "1.0.2"
	APP_SITE    = "https://github.com/feedtailor/SSLCheck"

	MAX_REDIRECT = 10

	EXIT_CODE_SUCCESS = 0
	EXIT_CODE_ERROR   = 1
)

var (
	app      = kingpin.New(fmt.Sprintf("%s %s", APP_NAME, APP_VERSION), "ssl check application.")
	dataFile = app.Flag("file", "name of data file").Short('f').String()
	logFile  = app.Flag("log", "name of log file").String()
	logDir   = app.Flag("log-dir", "name of log dir").Default("logs").String()

	userAgent = fmt.Sprintf("Mozilla/5.0 (compatible; %s/%s; +%s)", APP_NAME, APP_VERSION, APP_SITE)
)

var (
	logger     = logrus.New()
	httpClient *http.Client

	noscriptRegexp *regexp.Regexp

	noscriptBytes = []byte("<noscript>")
	emptyBytes    = []byte{}
)

type CertInfo struct {
	Country            []string
	Organization       []string
	OrganizationalUnit []string
	Locality           []string
	Province           []string
	StreetAddress      []string
	PostalCode         []string
	CommonName         string

	IssuerCountry            []string
	IssuerOrganization       []string
	IssuerOrganizationalUnit []string
	IssuerCommonName         string

	NotBefore time.Time
	NotAfter  time.Time
}

func processRow(code, issue, orig_url string) (string, string, *CertInfo) {
	logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": orig_url}).Debug()
	if orig_url == "" {
		return "", "", nil
	}
	count := 0
	st, u := checkSslEnabled(code, issue, orig_url, count)

	var cert *CertInfo
	if strings.HasPrefix(u, "https://") {
		cert = checkCertificate(u)
	}
	if cert != nil {
		logger.WithFields(logrus.Fields{"code": code, "issue": issue, "ssl_url": u, "status": st,
			"CN":        cert.CommonName,
			"C":         strings.Join(cert.Country, ";"),
			"PC":        strings.Join(cert.PostalCode, ";"),
			"STREET":    strings.Join(cert.StreetAddress, ";"),
			"ST":        strings.Join(cert.Province, ";"),
			"L":         strings.Join(cert.Locality, ";"),
			"O":         strings.Join(cert.Organization, ";"),
			"OU":        strings.Join(cert.OrganizationalUnit, ";"),
			"Issuer-CN": cert.IssuerCommonName,
			"Issuer-O":  strings.Join(cert.IssuerOrganization, ";"),
			"Validity":  formatValidity(cert),
			"Type":      certType(cert)}).Debug()
	}
	return st, u, cert
}

func checkSslEnabled(code, issue, orig_url string, count int) (string, string) {
	ssl_url := "https://" + orig_url[strings.Index(orig_url, "://")+3:]
	resp, err := httpGet(ssl_url)
	if err != nil {
		logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "orig_url": orig_url}).Warnf("Request error: %v", err)
		errMsg := err.Error()
		if strings.Contains(errMsg, "Client.Timeout") ||
			strings.Contains(errMsg, "i/o timeout") ||
			strings.Contains(errMsg, "EOF") ||
			strings.Contains(errMsg, "getsockopt: connection refused") ||
			strings.Contains(errMsg, "getsockopt: network is unreachable") ||
			strings.Contains(errMsg, "read: connection reset by peer") ||
			strings.Contains(errMsg, "http: server gave HTTP response to HTTPS client") ||
			strings.Contains(errMsg, "tls: internal error") ||
			strings.Contains(errMsg, "tls: alert") ||
			strings.Contains(errMsg, "tls: oversized record received") ||
			strings.Contains(errMsg, "tls: first record does not look like a TLS handshake") {
			return "-1", orig_url
		} else if strings.Contains(errMsg, "certificate is valid for") {
			return "hostname error", orig_url
		} else if strings.Contains(errMsg, "has expired") {
			return "expired", orig_url
		} else if strings.Contains(errMsg, "unknown authority") {
			certInfo := getCertInfo(err.(*url.Error).Err.(x509.UnknownAuthorityError).Cert)
			if isKnownAuthority(certInfo.IssuerCommonName) {
				return "unknown authority", ssl_url
			}
			return "unknown authority", orig_url
		} else {
			return errMsg, orig_url
		}
	}
	status := resp.StatusCode
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "orig_url": orig_url}).Errorf("Read error: %v", err)
		return err.Error(), orig_url
	}
	resp.Body.Close()

	switch {
	case status >= 200 && status < 300:
		// 処理継続
		refresh := resp.Header.Get("refresh")
		if refresh != "" {
			loc := refresh[strings.IndexRune(refresh, '=')+1:]
			logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "orig_url": orig_url, "location": loc}).Info("Redirect: header refresh")
			loc = getAbsolutePath(ssl_url, loc)
			return strconv.Itoa(status), loc
		}
		if bytes.Contains(b, noscriptBytes) {
			b = noscriptRegexp.ReplaceAll(b, emptyBytes)
		}
		var doc *goquery.Document
		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(b))
		if err != nil {
			logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "orig_url": orig_url}).Errorf("Scraping error: %v", err)
			return strconv.Itoa(status), orig_url
		}
		meta := doc.Find("meta")
		var content, equiv string
		for _, node := range meta.Nodes {
			for _, attr := range node.Attr {
				switch attr.Key {
				case "content":
					content = attr.Val
				case "http-equiv":
					equiv = attr.Val
				}
			}
			if strings.ToLower(equiv) == "refresh" {
				loc := strings.TrimSpace(content[strings.IndexRune(content, '=')+1:])
				logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "orig_url": orig_url, "location": loc}).Info("Redirect: meta refresh")
				loc = getAbsolutePath(ssl_url, loc)
				count++
				if orig_url == loc || ssl_url == loc || count >= MAX_REDIRECT {
					logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "orig_url": orig_url, "status": status, "location": loc}).Warn("Redirect loop: meta refresh")
					return strconv.Itoa(status), loc
				}
				if strings.HasPrefix(strings.ToLower(loc), "https://") {
					return checkSslEnabled(code, issue, loc, count)
				}
				return strconv.Itoa(status), loc
			}
		}
		logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "orig_url": orig_url, "status": status}).Info()
		return strconv.Itoa(status), ssl_url
	case status >= 300 && status < 400:
		loc := resp.Header.Get("Location")
		logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "orig_url": orig_url, "status": status, "location": loc}).Info("Redirect")
		loc = getAbsolutePath(ssl_url, loc)
		count++
		if orig_url == loc || ssl_url == loc || count >= MAX_REDIRECT {
			logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "orig_url": orig_url, "status": status, "location": loc}).Warn("Redirect loop")
			return strconv.Itoa(status), loc
		}
		if strings.HasPrefix(strings.ToLower(loc), "https://") {
			return checkSslEnabled(code, issue, loc, count)
		}
		return strconv.Itoa(status), loc
	default:
		logger.WithFields(logrus.Fields{"code": code, "issue": issue, "url": ssl_url, "status": status}).Warn()
		return strconv.Itoa(status), orig_url
	}
}

func getAbsolutePath(url, loc string) string {
	if !strings.HasPrefix(strings.ToLower(loc), "http") {
		if strings.HasPrefix(loc, "/") {
			loc = url[0:strings.IndexRune(url[9:], '/')+9] + loc
		} else {
			loc = url + loc
		}
	}
	return loc
}

func checkCertificate(ssl_url string) *CertInfo {
	u, err := url.Parse(ssl_url)
	if err != nil {
		logger.WithFields(logrus.Fields{"url": ssl_url}).Errorf("URL Error: %v", err)
		return nil
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	config := tls.Config{}
	conn, err := tls.Dial("tcp", host+":"+port, &config)
	if err != nil {
		logger.WithFields(logrus.Fields{"url": ssl_url, "host": host, "port": port}).Errorf("SSL error: %v", err)
		if strings.Contains(err.Error(), "unknown authority") {
			certInfo := getCertInfo(err.(x509.UnknownAuthorityError).Cert)
			if isKnownAuthority(certInfo.IssuerCommonName) {
				return getCertInfo(err.(x509.UnknownAuthorityError).Cert)
			}
		}
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return findCertificate(host, state.PeerCertificates)
}

func isKnownAuthority(cn string) bool {
	if strings.Contains(cn, "AlphaSSL") ||
		strings.Contains(cn, "COMODO") ||
		strings.Contains(cn, "Cybertrust") ||
		strings.Contains(cn, "DigiCert") ||
		strings.Contains(cn, "GeoTrust") ||
		strings.Contains(cn, "GlobalSign") ||
		strings.Contains(cn, "RapidSSL") ||
		strings.Contains(cn, "Symantec") ||
		strings.Contains(cn, "thawte") {
		return true
	}
	return false
}

func getCertInfo(c *x509.Certificate) *CertInfo {
	certInfo := &CertInfo{}
	certInfo.Country = c.Subject.Country                       // C
	certInfo.Organization = c.Subject.Organization             // O
	certInfo.OrganizationalUnit = c.Subject.OrganizationalUnit // OU
	certInfo.Locality = c.Subject.Locality                     // L
	certInfo.Province = c.Subject.Province                     // ST
	certInfo.StreetAddress = c.Subject.StreetAddress           // StreetAddress (STREET)
	certInfo.PostalCode = c.Subject.PostalCode                 // PostalCode (PC)
	certInfo.CommonName = c.Subject.CommonName                 // CN
	certInfo.IssuerOrganization = c.Issuer.Organization
	certInfo.IssuerOrganizationalUnit = c.Issuer.OrganizationalUnit
	certInfo.IssuerCommonName = c.Issuer.CommonName
	certInfo.NotBefore = c.NotBefore
	certInfo.NotAfter = c.NotAfter
	return certInfo
}

func findCertificate(host string, certs []*x509.Certificate) (certInfo *CertInfo) {
	var c *x509.Certificate
	for _, cert := range certs {
		if host == cert.Subject.CommonName {
			c = cert
			break
		} else if strings.HasPrefix(cert.Subject.CommonName, "*.") && strings.HasSuffix(host, cert.Subject.CommonName[1:]) {
			c = cert
			break
		}
		for _, name := range cert.DNSNames {
			if host == name {
				c = cert
				break
			} else if strings.HasPrefix(name, "*.") && strings.HasSuffix(host, name[1:]) {
				c = cert
				break
			}

		}
	}
	if c != nil {
		certInfo = getCertInfo(c)
	} else {
		logger.WithFields(logrus.Fields{"host": host}).Warnf("Certificate not found")
	}
	return certInfo
}

func httpGet(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.WithFields(logrus.Fields{"url": url}).Errorf("Get error: %v", err)
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept-Language", "ja,en-US;q=0.8,en;q=0.6")
	return httpClient.Do(req)
}

func createHTTPClient() *http.Client {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(5) * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConnsPerHost:   1,
		ResponseHeaderTimeout: time.Duration(30) * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
	}
	err := http2.ConfigureTransport(transport)
	if err != nil {
		exitWithMsg(fmt.Sprintf("Failed to init HTTP client: %v", err), EXIT_CODE_ERROR)
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client
}

func init() {
	kingpin.Version(APP_VERSION)
	kingpin.MustParse(app.Parse(os.Args[1:]))

	if *dataFile != "" && !filepath.IsAbs(*dataFile) {
		*dataFile, _ = filepath.Abs(*dataFile)
	}
	if !filepath.IsAbs(*logDir) {
		*logDir, _ = filepath.Abs(*logDir)
	}
	_, err := os.Stat(*logDir)
	if err != nil {
		err = os.MkdirAll(*logDir, 0777)
		if err != nil {
			exitWithMsg("Could not write to logfile", EXIT_CODE_ERROR)
		}
	}
	if *logFile == "" {
		*logFile = time.Now().Format("sslcheck.200601021504.log")
	}
	logfile, err := os.OpenFile(path.Join(*logDir, *logFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		exitWithMsg(fmt.Sprintf("%v", err), EXIT_CODE_ERROR)
	}
	logger.Out = logfile
	logger.Level = logrus.DebugLevel

	httpClient = createHTTPClient()
	noscriptRegexp, _ = regexp.Compile("</?noscript>")
}

func formatValidity(cert *CertInfo) string {
	return fmt.Sprintf("%s - %s", cert.NotBefore.Format("2006/01/02"), cert.NotAfter.Format("2006/01/02"))
}

func certType(cert *CertInfo) string {
	issuer := cert.IssuerCommonName
	if issuer == "" {
		return "-"
	}
	if strings.Contains(issuer, "Extended Validation") || strings.Contains(issuer, "EV") {
		return "EV"
	}
	if strings.Contains(issuer, "Organization Validation") || strings.Contains(issuer, "OV") {
		return "OV"
	}
	if strings.Contains(issuer, "Domain Validation") || strings.Contains(issuer, "DV") {
		return "DV"
	}
	if cert.Country != nil && cert.Organization != nil {
		return "OV"
	}
	return "DV"
}

func write(a []string) {
	fmt.Println(strings.Join(a, "\t"))
}

func main() {
	var reader *csv.Reader
	if *dataFile == "" {
		logger.Debug("read from stdin")
		reader = csv.NewReader(os.Stdin)
	} else {
		logger.Debugf("read from %s", *dataFile)
		f, err := os.Open(*dataFile)
		if err != nil {
			exitWithMsg(fmt.Sprintf("%v", err), EXIT_CODE_ERROR)
		}
		defer f.Close()
		reader = csv.NewReader(f)
	}
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			exitWithMsg(fmt.Sprintf("%v", err), EXIT_CODE_ERROR)
		}
		// for JPX topix format: https://www.jpx.co.jp/markets/statistics-equities/misc/01.html
		if len(record) > 10 {
			code := record[1]
			issue := record[2]
			orig_url := record[10]
			if orig_url == "URL" {
				write(append(record, []string{
					"SSL Verified URL", "Status", "CN", "C", "L", "O", "OU", "Issuer-CN", "Issuer-O", "Validity", "Type",
				}...))
				continue
			} else {
				st, checked_url, cert := processRow(code, issue, orig_url)
				if cert != nil {
					write(append(record, []string{
						checked_url,
						st,
						cert.CommonName,
						strings.Join(cert.Country, ";"),
						strings.Join(cert.Locality, ";"),
						strings.Join(cert.Organization, ";"),
						strings.Join(cert.OrganizationalUnit, ";"),
						cert.IssuerCommonName,
						strings.Join(cert.IssuerOrganization, ";"),
						formatValidity(cert),
						certType(cert),
					}...))
				} else {
					write(append(record, []string{
						checked_url, st, "", "", "", "", "", "", "", "", "",
					}...))
				}
			}
		} else if len(record) == 1 {
			orig_url := record[0]
			if orig_url == "URL" {
				write(append(record, []string{
					"SSL Verified URL", "Status", "CN", "C", "L", "O", "OU", "Issuer-CN", "Issuer-O", "Validity", "Type",
				}...))
				continue
			} else {
				st, checked_url, cert := processRow("-", "-", orig_url)
				if cert != nil {
					write(append(record, []string{
						checked_url,
						st,
						cert.CommonName,
						strings.Join(cert.Country, ";"),
						strings.Join(cert.Locality, ";"),
						strings.Join(cert.Organization, ";"),
						strings.Join(cert.OrganizationalUnit, ";"),
						cert.IssuerCommonName,
						strings.Join(cert.IssuerOrganization, ";"),
						formatValidity(cert),
						certType(cert),
					}...))
				} else {
					write(append(record, []string{
						checked_url, st, "", "", "", "", "", "", "", "", "",
					}...))
				}
			}
		}
	}
	os.Exit(EXIT_CODE_SUCCESS)
}

func exitWithMsg(msg string, exitCode int) {
	logger.Errorln(msg)
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(exitCode)
}
