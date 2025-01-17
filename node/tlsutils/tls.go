package tlsutils

import (
	"crypto/tls"
	"crypto/x509"
	"embed"
)

//go:embed ca.pem
//go:embed cert.pem
//go:embed priv.key
var fs embed.FS

func GetTLSConfig() *tls.Config {
	cert, err := fs.ReadFile("cert.pem")
	if err != nil {
		panic(err)
	}
	key, err := fs.ReadFile("priv.key")
	if err != nil {
		panic(err)
	}
	ca, err := fs.ReadFile("ca.pem")
	if err != nil {
		panic(err)
	}
	keyPair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		panic(err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(ca) {
		panic("failed to append ca certs")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}
}
