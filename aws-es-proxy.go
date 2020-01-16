package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	signer "github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/sirupsen/logrus"
)

type proxy struct {
	scheme      string
	host        string
	region      string
	service     string
	endpoint    string
	nosignreq   bool
	credentials *credentials.Credentials
}

var client = &http.Client{
	CheckRedirect: noRedirect,
}

func noRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

func newProxy(endpoint string) (*proxy, error) {
	p := &proxy{endpoint: endpoint}

	link, err := url.Parse(p.endpoint)
	if err != nil {
		return nil, fmt.Errorf("error: failure while parsing endpoint: %s. Error: %s",
			p.endpoint, err.Error())
	}

	// Only http/https are supported schemes
	switch link.Scheme {
	case "http", "https":
	default:
		link.Scheme = "https"
	}

	// Unknown schemes sometimes result in empty host value
	if link.Host == "" {
		return nil, fmt.Errorf("error: empty host or protocol information in submitted endpoint (%s)",
			p.endpoint)
	}

	// AWS SignV4 enabled, extract required parts for signing process
	if !p.nosignreq {
		// Extract region and service from link
		parts := strings.Split(link.Host, ".")

		if len(parts) == 5 {
			p.region, p.service = parts[1], parts[2]
		} else {
			return nil, fmt.Errorf("error: submitted endpoint is not a valid Amazon ElasticSearch Endpoint")
		}
	}

	// Update proxy struct
	p.scheme = link.Scheme
	p.host = link.Host

	return p, nil
}

func (p *proxy) getSigner() *signer.Signer {
	// Refresh credentials after expiration. Required for STS
	if p.credentials == nil {
		sess := session.Must(session.NewSession())
		credentials := sess.Config.Credentials
		p.credentials = credentials
		log.Info("Generated fresh AWS Credentials object")
	}
	return signer.NewSigner(p.credentials)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	url := *req.URL
	url.Host = p.host
	url.Scheme = p.scheme
	url.Path = path.Clean(url.Path)

	proxyReq, err := http.NewRequest(req.Method, url.String(), req.Body)
	if err != nil {
		log.Fatalln("error creating new request. ", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addHeaders(req.Header, proxyReq.Header)

	// Make signV4 optional
	if !p.nosignreq {
		s := p.getSigner()
		// Start AWS session from ENV, Shared Creds or EC2Role
		payload := bytes.NewReader(replaceBody(proxyReq))
		s.Sign(proxyReq, payload, p.service, p.region, time.Now())
	}
	log.Info("Proxying request to ES")
	resp, err := client.Do(proxyReq)
	if err != nil {
		log.Fatalln(err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !p.nosignreq {
		// AWS credentials expired, need to generate fresh ones
		if resp.StatusCode == 403 {
			p.credentials = nil
			return
		}
	}

	defer resp.Body.Close()

	// Write back headers to requesting client
	copyHeaders(w.Header(), resp.Header)

	// Send response back to requesting client
	body := bytes.Buffer{}
	if _, err := io.Copy(&body, resp.Body); err != nil {
		log.Fatalln(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body.Bytes())
}

// Recent versions of ES/Kibana require
// "kbn-version" and "content-type: application/json"
// headers to exist in the request.
// If missing requests fails.
func addHeaders(src, dest http.Header) {
	if val, ok := src["Kbn-Version"]; ok {
		dest.Add("Kbn-Version", val[0])
	}

	if val, ok := src["Content-Type"]; ok {
		dest.Add("Content-Type", val[0])
	}
}

// Signer.Sign requires a "seekable" body to sum body's sha256
func replaceBody(req *http.Request) []byte {
	if req.Body == nil {
		return []byte{}
	}
	payload, _ := ioutil.ReadAll(req.Body)
	req.Body = ioutil.NopCloser(bytes.NewReader(payload))
	return payload
}

func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func getEnv(name, def string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	}
	return def
}

func main() {
	var err error
	endpoint := getEnv("ES_ENDPOINT", "")
	nosignreq := getEnv("ES_NO_SIGN", "0") == "1"
	listenAddress := getEnv("LISTEN_ADDRESS", "0.0.0.0:80")

	if endpoint == "" {
		fmt.Println("You need to specify Amazon ElasticSearch endpoint via environment variable ES_ENDPOINT.")
		os.Exit(1)
	}

	p, err := newProxy(endpoint)
	if err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
	p.nosignreq = nosignreq

	log.Info("Listening on %s...\n", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, p))
}
