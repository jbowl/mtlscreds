package mtlscreds

/*
Package mtlscreds provides client and server functions that return necessary
credentials.TransportCredentials for mutual TLS.

TODO: a modicum of testing
*/

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"os"

	"google.golang.org/grpc/credentials"
)

// SvrCreds - returns credentials.TransportCredentials
func SvrCreds(rootcert string, svrcert string, svrkey string) (credentials.TransportCredentials, error) {

	bytes, err := os.ReadFile(rootcert)
	if err != nil {
		return nil, err
	}

	// cert pool for this microservice

	// need to add our CA cert to the cert pool cause it isn't know a public CA
	//
	//	and isn't known otherwise
	cp := x509.NewCertPool() // or system pool    cp ,err := x509.SystemCertPool()

	if !cp.AppendCertsFromPEM(bytes) {
		log.Println("credentials: failed to append certificates")
		return nil, errors.New("credentials: failed to append certificates")
	}

	// CERT for this server,
	certPem := os.Getenv("SVR_CERT")
	keyPem := os.Getenv("SVR_KEY")

	cert, err := tls.LoadX509KeyPair(certPem, keyPem)
	if err != nil {
		log.Printf("tls.LoadPair %v\n", err)
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert}, //this
		ClientCAs:    cp,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		//	GetCertificate:        CertReqFunc(certPem, keyPem), // or
		//	VerifyPeerCertificate: CertificateChains,            //these
	}

	return credentials.NewTLS(config), nil

}

// ClientCreds - returns credentials.TransportCredentials
func ClientCreds(rootcert string, svrcert string, svrkey string) (credentials.TransportCredentials, error) {

	bytes, err := os.ReadFile(rootcert)
	if err != nil {
		return nil, err
	}
	// cert pool for this microservice

	// need to add our CA cert to the cert pool cause it isn't know a public CA
	//  and isn't known otherwise
	cp := x509.NewCertPool() // or system pool    cp ,err := x509.SystemCertPool()

	if !cp.AppendCertsFromPEM(bytes) {
		return nil, errors.New("credentials: failed to append certificates")
	}

	cert, err := tls.LoadX509KeyPair(svrcert, svrkey)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert}, //this
		RootCAs:      cp,                      // trusted certs
		//		GetClientCertificate:  ClientCertReqFunc(certpem, keypem), // or
		//		VerifyPeerCertificate: CertificateChains,                  //these
	}

	return credentials.NewTLS(config), nil
}
