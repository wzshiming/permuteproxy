package testutils

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
)

func TestIssueSignsALeafForTheNameWithTheCA(t *testing.T) {
	caFile, certFile, keyFile := Issue(t, "issued.test")
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatalf("%s holds no PEM certificate", caFile)
	}
	if _, err := pair.Leaf.Verify(x509.VerifyOptions{DNSName: "issued.test", Roots: roots}); err != nil {
		t.Fatalf("the leaf does not verify for issued.test under the CA: %v", err)
	}
}
