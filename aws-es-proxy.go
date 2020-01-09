package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/golang/glog"
)

type requestStruct struct {
	Requestid  string
	Datetime   string
	Remoteaddr string
	Requesturi string
	Method     string
	Statuscode int
	Elapsed    float64
	Body       string
}

type responseStruct struct {
	Requestid string
	Body      string
}

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

func newProxy(args ...interface{}) *proxy {
	return &proxy{
		endpoint:  args[0].(string),
		nosignreq: args[1].(bool),
	}
}

func (p *proxy) parseEndpoint() error {
	var link *url.URL
	var err error

	if link, err = url.Parse(p.endpoint); err != nil {
		return fmt.Errorf("error: failure while parsing endpoint: %s. Error: %s",
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
		return fmt.Errorf("error: empty host or protocol information in submitted endpoint (%s)",
			p.endpoint)
	}

	// AWS SignV4 enabled, extract required parts for signing process
	if !p.nosignreq {
		// Extract region and service from link
		parts := strings.Split(link.Host, ".")

		if len(parts) == 5 {
			p.region, p.service = parts[1], parts[2]
		} else {
			return fmt.Errorf("error: submitted endpoint is not a valid Amazon ElasticSearch Endpoint")
		}
	}

	// Update proxy struct
	p.scheme = link.Scheme
	p.host = link.Host

	return nil
}

func (p *proxy) getSigner() *v4.Signer {
	// Refresh credentials after expiration. Required for STS
	if p.credentials == nil {
		sess := session.Must(session.NewSession())
		credentials := sess.Config.Credentials
		p.credentials = credentials
		glog.Info("Generated fresh AWS Credentials object")
	}
	return v4.NewSigner(p.credentials)
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	url := *req.URL
	url.Host = p.host
	url.Scheme = p.scheme
	url.Path = path.Clean(url.Path)

	proxyReq, err := http.NewRequest(req.Method, url.String(), req.Body)
	if err != nil {
		glog.Fatalln("error creating new request. ", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addHeaders(req.Header, proxyReq.Header)

	// Make signV4 optional
	if !p.nosignreq {
		signer := p.getSigner()
		// Start AWS session from ENV, Shared Creds or EC2Role
		payload := bytes.NewReader(replaceBody(proxyReq))
		signer.Sign(proxyReq, payload, p.service, p.region, time.Now())
	}
	glog.Info("Proxying request to ES")
	resp, err := client.Do(proxyReq)
	if err != nil {
		glog.Fatalln(err.Error())
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

func init() {
	flag.Set("logtostderr", "true")
	flag.Set("stderrthreshold", "WARNING")
	flag.Set("v", "2")
}

func main() {

	var (
		nosignreq     bool
		endpoint      string
		listenAddress string
		err           error
	)

	flag.StringVar(&endpoint, "endpoint", "", "Amazon ElasticSearch Endpoint (e.g: https://dummy-host.eu-west-1.es.amazonaws.com)")
	flag.StringVar(&listenAddress, "listen", "127.0.0.1:9200", "Local TCP port to listen on")
	flag.BoolVar(&nosignreq, "no-sign-reqs", false, "Disable AWS Signature v4")
	flag.Parse()

	if len(os.Args) < 3 {
		fmt.Println("You need to specify Amazon ElasticSearch endpoint.")
		fmt.Println("Please run with '-h' for a list of available arguments.")
		os.Exit(1)
	}

	p := newProxy(
		endpoint,
		nosignreq,
	)

	if err = p.parseEndpoint(); err != nil {
		glog.Fatalln(err)
		os.Exit(1)
	}

	glog.Info("Listening on %s...\n", listenAddress)
	glog.Fatal(http.ListenAndServe(listenAddress, p))
}
