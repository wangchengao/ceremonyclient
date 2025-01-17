package main

import (
	"log"
	"net/http"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/qlog"
	"source.quilibrium.com/quilibrium/monorepo/node/tlsutils"
)

func TestInitQuicServer(t *testing.T) {
	tlsConfig := tlsutils.GetTLSConfig()
	tlsConfig.InsecureSkipVerify = true

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: tlsConfig,
		QUICConfig: &quic.Config{
			Tracer: qlog.DefaultTracer,
		},
	}
	defer roundTripper.Close()
	hclient := &http.Client{
		Transport: roundTripper,
	}

	rsp, err := hclient.Post("http://localhost:8081", "application/json", nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Got response for %s: %#v", "http://localhost:8081", rsp)

}
