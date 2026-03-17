package tlsmanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing and returns PEM-encoded cert and key.
func generateTestCert(t *testing.T, cn string, dnsNames []string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

// writeTestCertFiles writes cert and key PEM to temp files and returns paths.
func writeTestCertFiles(t *testing.T, certPEM, keyPEM []byte) (certFile, keyFile string) {
	t.Helper()

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	return certFile, keyFile
}

// --- Manager Tests ---

func TestLoadCertificateFromFiles(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "test.example.com", []string{"test.example.com"})
	certFile, keyFile := writeTestCertFiles(t, certPEM, keyPEM)

	m := NewManager()
	err := m.LoadCertificate(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCertificate failed: %v", err)
	}

	if !m.HasDefaultCert() {
		t.Error("expected default certificate to be set")
	}
}

func TestLoadCertificateInvalidFiles(t *testing.T) {
	m := NewManager()
	err := m.LoadCertificate("/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error loading non-existent files")
	}
}

func TestSNIRoutingMultipleCerts(t *testing.T) {
	m := NewManager()

	// Create certs for two domains
	cert1PEM, key1PEM := generateTestCert(t, "alpha.example.com", []string{"alpha.example.com"})
	cert2PEM, key2PEM := generateTestCert(t, "beta.example.com", []string{"beta.example.com"})

	tlsCert1, err := tls.X509KeyPair(cert1PEM, key1PEM)
	if err != nil {
		t.Fatalf("failed to parse cert1: %v", err)
	}
	tlsCert2, err := tls.X509KeyPair(cert2PEM, key2PEM)
	if err != nil {
		t.Fatalf("failed to parse cert2: %v", err)
	}

	m.AddCertificate("alpha.example.com", &tlsCert1)
	m.AddCertificate("beta.example.com", &tlsCert2)

	if m.CertificateCount() != 2 {
		t.Errorf("expected 2 certificates, got %d", m.CertificateCount())
	}

	// Test SNI routing for alpha
	hello1 := &tls.ClientHelloInfo{ServerName: "alpha.example.com"}
	got1, err := m.GetCertificate(hello1)
	if err != nil {
		t.Fatalf("GetCertificate failed for alpha: %v", err)
	}
	if got1 != &tlsCert1 {
		t.Error("got wrong certificate for alpha.example.com")
	}

	// Test SNI routing for beta
	hello2 := &tls.ClientHelloInfo{ServerName: "beta.example.com"}
	got2, err := m.GetCertificate(hello2)
	if err != nil {
		t.Fatalf("GetCertificate failed for beta: %v", err)
	}
	if got2 != &tlsCert2 {
		t.Error("got wrong certificate for beta.example.com")
	}
}

func TestSNIWildcardMatch(t *testing.T) {
	m := NewManager()

	certPEM, keyPEM := generateTestCert(t, "*.example.com", []string{"*.example.com"})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse wildcard cert: %v", err)
	}

	m.AddCertificate("*.example.com", &tlsCert)

	// Should match sub.example.com via wildcard
	hello := &tls.ClientHelloInfo{ServerName: "sub.example.com"}
	got, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed for wildcard: %v", err)
	}
	if got != &tlsCert {
		t.Error("wildcard certificate not matched")
	}
}

func TestSNIFallbackToDefault(t *testing.T) {
	m := NewManager()

	certPEM, keyPEM := generateTestCert(t, "default.example.com", []string{"default.example.com"})
	defaultCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse default cert: %v", err)
	}
	m.SetDefaultCertificate(&defaultCert)

	// Unknown domain should fall back to default
	hello := &tls.ClientHelloInfo{ServerName: "unknown.example.com"}
	got, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed for fallback: %v", err)
	}
	if got != &defaultCert {
		t.Error("expected fallback to default certificate")
	}
}

func TestSNINoMatchNoDefault(t *testing.T) {
	m := NewManager()

	hello := &tls.ClientHelloInfo{ServerName: "unknown.example.com"}
	_, err := m.GetCertificate(hello)
	if err == nil {
		t.Error("expected error when no certificate and no default")
	}
}

func TestGetCertificateCaseInsensitive(t *testing.T) {
	m := NewManager()

	certPEM, keyPEM := generateTestCert(t, "example.com", []string{"example.com"})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	m.AddCertificate("Example.Com", &tlsCert)

	// Lookup should be case-insensitive
	hello := &tls.ClientHelloInfo{ServerName: "example.com"}
	got, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if got != &tlsCert {
		t.Error("case-insensitive lookup failed")
	}
}

// --- Self-Signed Generation ---

func TestGenerateSelfSigned(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"localhost", "127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one certificate in chain")
	}

	// Parse and validate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse generated certificate: %v", err)
	}

	if x509Cert.Subject.Organization[0] != "GuardianWAF Self-Signed" {
		t.Errorf("unexpected organization: %v", x509Cert.Subject.Organization)
	}

	// Check SANs
	foundLocalhost := false
	for _, name := range x509Cert.DNSNames {
		if name == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Error("expected 'localhost' in DNS SANs")
	}

	foundIP := false
	for _, ip := range x509Cert.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Error("expected 127.0.0.1 in IP SANs")
	}

	// Verify key type
	if _, ok := cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Error("expected ECDSA private key")
	}
}

func TestGenerateSelfSignedDefaultHosts(t *testing.T) {
	cert, err := GenerateSelfSigned(nil)
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if len(x509Cert.DNSNames) == 0 {
		t.Error("expected default DNS names")
	}
}

// --- TLS Config ---

func TestTLSConfig(t *testing.T) {
	m := NewManager()
	cfg := m.TLSConfig()

	if cfg == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if cfg.GetCertificate == nil {
		t.Error("expected GetCertificate callback")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("expected MinVersion TLS 1.2, got %d", cfg.MinVersion)
	}
	if len(cfg.NextProtos) != 2 || cfg.NextProtos[0] != "h2" || cfg.NextProtos[1] != "http/1.1" {
		t.Errorf("unexpected NextProtos: %v", cfg.NextProtos)
	}
}

// --- Save and Load Certificate ---

func TestSaveAndLoadCertificate(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"test.local"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	err = SaveCertificate(cert, certFile, keyFile)
	if err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert file not created: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("key file not created: %v", err)
	}

	// Load back
	m := NewManager()
	err = m.LoadCertificate(certFile, keyFile)
	if err != nil {
		t.Fatalf("LoadCertificate failed after save: %v", err)
	}
	if !m.HasDefaultCert() {
		t.Error("expected default cert after loading")
	}
}

// --- ACME Challenge Handler ---

func TestACMEChallengeHandler(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	// Set a challenge
	ac.SetChallenge("test-token-123", "test-token-123.thumbprint")

	handler := ac.HTTPChallengeHandler()

	// Test valid challenge request
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/test-token-123", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for valid challenge, got %d", rr.Code)
	}
	if rr.Body.String() != "test-token-123.thumbprint" {
		t.Errorf("expected key authorization, got %q", rr.Body.String())
	}
	if rr.Header().Get("Content-Type") != "text/plain" {
		t.Errorf("expected text/plain content type, got %q", rr.Header().Get("Content-Type"))
	}
}

func TestACMEChallengeHandlerNotFound(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	handler := ac.HTTPChallengeHandler()

	// Unknown token
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/unknown-token", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown token, got %d", rr.Code)
	}
}

func TestACMEChallengeHandlerWrongPath(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	handler := ac.HTTPChallengeHandler()

	// Non-challenge path
	req := httptest.NewRequest("GET", "/other/path", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-challenge path, got %d", rr.Code)
	}
}

func TestACMEClearChallenge(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	ac.SetChallenge("token1", "auth1")
	ac.ClearChallenge("token1")

	handler := ac.HTTPChallengeHandler()
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/token1", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 after clearing challenge, got %d", rr.Code)
	}
}

// --- SNI Helper Tests ---

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		expected bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "other.com", false},
		{"*.example.com", "sub.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "deep.sub.example.com", false}, // only one level
		{"Example.Com", "example.com", true},              // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.hostname, func(t *testing.T) {
			got := MatchesDomain(tt.pattern, tt.hostname)
			if got != tt.expected {
				t.Errorf("MatchesDomain(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.expected)
			}
		})
	}
}

func TestGetCertificateInfo(t *testing.T) {
	certPEM, _ := generateTestCert(t, "info.example.com", []string{"info.example.com", "www.info.example.com"})

	info, err := GetCertificateInfo(certPEM)
	if err != nil {
		t.Fatalf("GetCertificateInfo failed: %v", err)
	}

	if info.CommonName != "info.example.com" {
		t.Errorf("expected CN 'info.example.com', got %q", info.CommonName)
	}
	if len(info.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(info.DNSNames))
	}
}

func TestGetCertificateInfoInvalidPEM(t *testing.T) {
	_, err := GetCertificateInfo([]byte("not a pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// --- SNI Router ---

func TestSNIRouterAddDomainCertificate(t *testing.T) {
	m := NewManager()
	sr := NewSNIRouter(m)

	certPEM, keyPEM := generateTestCert(t, "domain.test", []string{"domain.test"})

	err := sr.AddDomainCertificate("domain.test", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("AddDomainCertificate failed: %v", err)
	}

	if m.CertificateCount() != 1 {
		t.Errorf("expected 1 certificate, got %d", m.CertificateCount())
	}

	// Verify it can be retrieved
	hello := &tls.ClientHelloInfo{ServerName: "domain.test"}
	cert, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if cert == nil {
		t.Error("expected non-nil certificate")
	}
}

func TestSNIRouterAddDomainCertificateFiles(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t, "files.test", []string{"files.test"})
	certFile, keyFile := writeTestCertFiles(t, certPEM, keyPEM)

	m := NewManager()
	sr := NewSNIRouter(m)

	err := sr.AddDomainCertificateFiles("files.test", certFile, keyFile)
	if err != nil {
		t.Fatalf("AddDomainCertificateFiles failed: %v", err)
	}

	if m.CertificateCount() != 1 {
		t.Errorf("expected 1 certificate, got %d", m.CertificateCount())
	}
}

func TestSNIRouterInvalidCert(t *testing.T) {
	m := NewManager()
	sr := NewSNIRouter(m)

	err := sr.AddDomainCertificate("bad.test", []byte("bad cert"), []byte("bad key"))
	if err == nil {
		t.Error("expected error for invalid certificate")
	}

	// Suppress unused import warning
	_ = strings.Contains
}

// ---------------------------------------------------------------------------
// ACME challenge handler edge cases
// ---------------------------------------------------------------------------

func TestACMEChallengeHandlerEmptyToken(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	handler := ac.HTTPChallengeHandler()

	// Empty token path (just the prefix with no token)
	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for empty token, got %d", rr.Code)
	}
}

func TestACMEChallengeSetAndGet(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	// Set multiple challenges
	ac.SetChallenge("token-a", "auth-a")
	ac.SetChallenge("token-b", "auth-b")

	handler := ac.HTTPChallengeHandler()

	// Verify both
	for _, tc := range []struct {
		token, auth string
	}{
		{"token-a", "auth-a"},
		{"token-b", "auth-b"},
	} {
		req := httptest.NewRequest("GET", "/.well-known/acme-challenge/"+tc.token, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 for %s, got %d", tc.token, rr.Code)
		}
		if rr.Body.String() != tc.auth {
			t.Errorf("expected %q, got %q", tc.auth, rr.Body.String())
		}
	}

	// Clear one and verify
	ac.ClearChallenge("token-a")

	req := httptest.NewRequest("GET", "/.well-known/acme-challenge/token-a", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 after clear, got %d", rr.Code)
	}

	// token-b should still work
	req = httptest.NewRequest("GET", "/.well-known/acme-challenge/token-b", nil)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 for token-b, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Certificate save/load round-trip with reload
// ---------------------------------------------------------------------------

func TestSaveCertificateNilCert(t *testing.T) {
	err := SaveCertificate(nil, "/tmp/cert.pem", "/tmp/key.pem")
	if err == nil {
		t.Error("expected error for nil certificate")
	}
}

func TestSaveCertificateEmptyCertData(t *testing.T) {
	cert := &tls.Certificate{}
	err := SaveCertificate(cert, "/tmp/cert.pem", "/tmp/key.pem")
	if err == nil {
		t.Error("expected error for empty certificate data")
	}
}

func TestSaveCertificateInvalidCertPath(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"test.local"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	err = SaveCertificate(cert, "/nonexistent/dir/cert.pem", "/nonexistent/dir/key.pem")
	if err == nil {
		t.Error("expected error for invalid cert path")
	}
}

func TestSaveCertificateInvalidKeyPath(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"test.local"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")

	err = SaveCertificate(cert, certFile, "/nonexistent/dir/key.pem")
	if err == nil {
		t.Error("expected error for invalid key path")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	// Generate a cert, save it, load it, and verify it works for TLS
	cert, err := GenerateSelfSigned([]string{"roundtrip.local", "127.0.0.1"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	err = SaveCertificate(cert, certFile, keyFile)
	if err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	// Verify we can read back and parse
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("failed to read cert file: %v", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	loaded, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse saved cert/key: %v", err)
	}
	if len(loaded.Certificate) == 0 {
		t.Error("expected at least one certificate")
	}

	// Parse and check SANs
	x509Cert, err := x509.ParseCertificate(loaded.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse x509: %v", err)
	}

	foundDomain := false
	for _, name := range x509Cert.DNSNames {
		if name == "roundtrip.local" {
			foundDomain = true
		}
	}
	if !foundDomain {
		t.Error("expected 'roundtrip.local' in DNS SANs after round-trip")
	}

	foundIP := false
	for _, ip := range x509Cert.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Error("expected 127.0.0.1 in IP SANs after round-trip")
	}
}

// ---------------------------------------------------------------------------
// Self-signed cert with multiple SANs
// ---------------------------------------------------------------------------

func TestGenerateSelfSignedMultipleSANs(t *testing.T) {
	hosts := []string{"app.example.com", "api.example.com", "10.0.0.1", "::1", "192.168.1.1"}
	cert, err := GenerateSelfSigned(hosts)
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	// Check DNS names
	if len(x509Cert.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d: %v", len(x509Cert.DNSNames), x509Cert.DNSNames)
	}

	// Check IP addresses
	if len(x509Cert.IPAddresses) != 3 {
		t.Errorf("expected 3 IP addresses, got %d: %v", len(x509Cert.IPAddresses), x509Cert.IPAddresses)
	}

	// Verify validity period
	if x509Cert.NotBefore.After(time.Now()) {
		t.Error("certificate NotBefore should be in the past")
	}
	if x509Cert.NotAfter.Before(time.Now()) {
		t.Error("certificate NotAfter should be in the future")
	}
}

// ---------------------------------------------------------------------------
// Manager with no certificates (fallback behavior)
// ---------------------------------------------------------------------------

func TestManagerNoCertificates(t *testing.T) {
	m := NewManager()

	if m.HasDefaultCert() {
		t.Error("new manager should not have default cert")
	}
	if m.CertificateCount() != 0 {
		t.Error("new manager should have 0 certificates")
	}

	// GetCertificate should fail
	hello := &tls.ClientHelloInfo{ServerName: "test.com"}
	_, err := m.GetCertificate(hello)
	if err == nil {
		t.Error("expected error when no certificates configured")
	}
}

// ---------------------------------------------------------------------------
// TLS Config cipher suites
// ---------------------------------------------------------------------------

func TestTLSConfigCipherSuites(t *testing.T) {
	m := NewManager()
	cfg := m.TLSConfig()

	expectedCiphers := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	if len(cfg.CipherSuites) != len(expectedCiphers) {
		t.Fatalf("expected %d cipher suites, got %d", len(expectedCiphers), len(cfg.CipherSuites))
	}

	for i, expected := range expectedCiphers {
		if cfg.CipherSuites[i] != expected {
			t.Errorf("cipher suite %d: expected %d, got %d", i, expected, cfg.CipherSuites[i])
		}
	}
}

// ---------------------------------------------------------------------------
// SNI wildcard matching edge cases
// ---------------------------------------------------------------------------

func TestSNIWildcardDoesNotMatchDeepSubdomain(t *testing.T) {
	m := NewManager()

	certPEM, keyPEM := generateTestCert(t, "*.example.com", []string{"*.example.com"})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse wildcard cert: %v", err)
	}

	m.AddCertificate("*.example.com", &tlsCert)

	// deep.sub.example.com should NOT match *.example.com
	hello := &tls.ClientHelloInfo{ServerName: "deep.sub.example.com"}
	_, err = m.GetCertificate(hello)
	if err == nil {
		t.Error("expected error for deep subdomain with wildcard cert (no default)")
	}
}

func TestSNICaseInsensitiveLookup(t *testing.T) {
	m := NewManager()

	certPEM, keyPEM := generateTestCert(t, "UPPER.example.com", []string{"UPPER.example.com"})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse cert: %v", err)
	}

	m.AddCertificate("UPPER.example.com", &tlsCert)

	// Lookup with mixed case
	hello := &tls.ClientHelloInfo{ServerName: "Upper.Example.Com"}
	got, err := m.GetCertificate(hello)
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}
	if got != &tlsCert {
		t.Error("case-insensitive lookup should match")
	}
}

// ---------------------------------------------------------------------------
// MatchesDomain additional edge cases
// ---------------------------------------------------------------------------

func TestMatchesDomainEdgeCases(t *testing.T) {
	tests := []struct {
		pattern  string
		hostname string
		expected bool
	}{
		{"*.example.com", "a.example.com", true},
		{"*.example.com", ".example.com", false},  // empty prefix
		{"*.example.com", "example.com", false},    // no subdomain
		{"example.com", "EXAMPLE.COM", true},       // case insensitive
		{"*.Example.COM", "sub.example.com", true}, // wildcard case insensitive
		{"abc.com", "abc.com", true},               // exact match
		{"abc.com", "xyz.com", false},              // no match
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.hostname, func(t *testing.T) {
			got := MatchesDomain(tt.pattern, tt.hostname)
			if got != tt.expected {
				t.Errorf("MatchesDomain(%q, %q) = %v, want %v", tt.pattern, tt.hostname, got, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SNI Router - AddDomainCertificateFiles with invalid files
// ---------------------------------------------------------------------------

func TestSNIRouterAddDomainCertificateFilesInvalid(t *testing.T) {
	m := NewManager()
	sr := NewSNIRouter(m)

	err := sr.AddDomainCertificateFiles("bad.test", "/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("expected error for invalid cert files")
	}
}

// ---------------------------------------------------------------------------
// GetCertificateInfo with invalid x509 data
// ---------------------------------------------------------------------------

func TestGetCertificateInfoInvalidX509(t *testing.T) {
	// Valid PEM block but invalid certificate data
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
	_, err := GetCertificateInfo(badPEM)
	if err == nil {
		t.Error("expected error for invalid x509 data")
	}
}

// ---------------------------------------------------------------------------
// ObtainCertificate
// ---------------------------------------------------------------------------

func TestObtainCertificateNoCacheDir(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	err := ac.ObtainCertificate()
	if err == nil {
		t.Error("expected error from ObtainCertificate stub")
	}
}

func TestObtainCertificateWithCachedCerts(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	// Generate and save a cert to the cache dir
	cert, err := GenerateSelfSigned([]string{"cached.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	err = SaveCertificate(cert, certPath, keyPath)
	if err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	ac := NewACMEClient("test@example.com", []string{"cached.example.com"}, dir, m)

	err = ac.ObtainCertificate()
	if err != nil {
		t.Fatalf("ObtainCertificate should succeed with cached cert: %v", err)
	}

	if !m.HasDefaultCert() {
		t.Error("expected default cert to be loaded from cache")
	}
}

func TestObtainCertificateCacheDirNoCert(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	// Cache dir exists but has no cert files
	ac := NewACMEClient("test@example.com", []string{"example.com"}, dir, m)

	err := ac.ObtainCertificate()
	if err == nil {
		t.Error("expected error when cache dir has no certs")
	}
}

func TestObtainCertificateCacheDirOnlyKeyNoCert(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	// Only key exists, no cert
	cert, err := GenerateSelfSigned([]string{"test.local"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	keyPath := filepath.Join(dir, "key.pem")
	certPath := filepath.Join(dir, "cert.pem")

	// Save only the key
	err = SaveCertificate(cert, certPath, keyPath)
	if err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}
	// Remove the cert file
	os.Remove(certPath)

	ac := NewACMEClient("test@example.com", []string{"test.local"}, dir, m)

	err = ac.ObtainCertificate()
	if err == nil {
		t.Error("expected error when cert file missing")
	}
}

// ---------------------------------------------------------------------------
// StartAutoRenewal
// ---------------------------------------------------------------------------

func TestStartAutoRenewalAndStop(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	stopCh := make(chan struct{})
	ac.StartAutoRenewal(stopCh)

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)

	// Stop it
	close(stopCh)

	// Just ensure no panic and it stops cleanly
	time.Sleep(50 * time.Millisecond)
}

// ---------------------------------------------------------------------------
// checkAndRenew
// ---------------------------------------------------------------------------

func TestCheckAndRenewNoCacheDir(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	// Should return early without error (cacheDir is empty)
	ac.checkAndRenew()
}

func TestCheckAndRenewNoCertFile(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	// Cache dir exists but cert.pem does not
	ac := NewACMEClient("test@example.com", []string{"example.com"}, dir, m)

	// Should try to obtain certificate (os.ReadFile error path)
	ac.checkAndRenew()
}

func TestCheckAndRenewWithValidCert(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	// Generate a cert that's valid for 1 year (not expiring soon)
	cert, err := GenerateSelfSigned([]string{"valid.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	err = SaveCertificate(cert, certPath, keyPath)
	if err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	ac := NewACMEClient("test@example.com", []string{"valid.example.com"}, dir, m)

	// Should not trigger renewal since cert is valid for ~1 year
	ac.checkAndRenew()
}

func TestCheckAndRenewWithInvalidPEM(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	certPath := filepath.Join(dir, "cert.pem")
	os.WriteFile(certPath, []byte("not a pem"), 0644)

	ac := NewACMEClient("test@example.com", []string{"example.com"}, dir, m)

	// Should handle invalid PEM gracefully
	ac.checkAndRenew()
}

func TestCheckAndRenewWithInvalidX509(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	certPath := filepath.Join(dir, "cert.pem")
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad x509")})
	os.WriteFile(certPath, badPEM, 0644)

	ac := NewACMEClient("test@example.com", []string{"example.com"}, dir, m)

	// Should handle invalid x509 gracefully
	ac.checkAndRenew()
}

func TestCheckAndRenewWithExpiringSoonCert(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	// Create a certificate that expires in 10 days (< 30 day threshold)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "expiring.example.com"},
		NotBefore:    time.Now().Add(-350 * 24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 24 * time.Hour), // Expires in 10 days
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certPath := filepath.Join(dir, "cert.pem")
	os.WriteFile(certPath, certPEM, 0644)

	ac := NewACMEClient("test@example.com", []string{"expiring.example.com"}, dir, m)

	// Should trigger renewal attempt (which will fail since ACME is not implemented)
	ac.checkAndRenew()
}

// ---------------------------------------------------------------------------
// SaveCertificate with non-ECDSA key (PKCS8 default branch)
// ---------------------------------------------------------------------------

func TestSaveCertificateWithRSAKey(t *testing.T) {
	// Generate an RSA-based certificate to hit the default branch in SaveCertificate
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "rsa.test.local"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create RSA certificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	err = SaveCertificate(&tlsCert, certFile, keyFile)
	if err != nil {
		t.Fatalf("SaveCertificate with RSA key failed: %v", err)
	}

	// Verify both files were created
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert file not created: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Errorf("key file not created: %v", err)
	}

	// Verify the key file contains PRIVATE KEY (PKCS8) block
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Error("expected PRIVATE KEY block in key file")
	}
}

// ---------------------------------------------------------------------------
// ObtainCertificate - cert exists but key does not
// ---------------------------------------------------------------------------

func TestObtainCertificateCertExistsKeyMissing(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	// Create only the cert file
	cert, err := GenerateSelfSigned([]string{"test.local"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// Save both, then remove the key
	err = SaveCertificate(cert, certPath, keyPath)
	if err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}
	os.Remove(keyPath)

	ac := NewACMEClient("test@example.com", []string{"test.local"}, dir, m)

	// cert exists but key doesn't - should fall through to error
	err = ac.ObtainCertificate()
	if err == nil {
		t.Error("expected error when key file missing")
	}
}

// ---------------------------------------------------------------------------
// ObtainCertificate - reuse existing account key
// ---------------------------------------------------------------------------

func TestObtainCertificateReusesAccountKey(t *testing.T) {
	m := NewManager()
	ac := NewACMEClient("test@example.com", []string{"example.com"}, "", m)

	// First call generates account key
	ac.ObtainCertificate()

	// Second call should reuse the same account key (no error from key generation)
	err := ac.ObtainCertificate()
	if err == nil {
		t.Error("expected error (stub not implemented)")
	}
}

// ---------------------------------------------------------------------------
// GenerateSelfSigned - domains only (no IPs)
// ---------------------------------------------------------------------------

func TestGenerateSelfSignedDomainsOnly(t *testing.T) {
	cert, err := GenerateSelfSigned([]string{"app.example.com", "www.example.com"})
	if err != nil {
		t.Fatalf("GenerateSelfSigned failed: %v", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	if len(x509Cert.DNSNames) != 2 {
		t.Errorf("expected 2 DNS names, got %d", len(x509Cert.DNSNames))
	}
	if len(x509Cert.IPAddresses) != 0 {
		t.Errorf("expected 0 IP addresses, got %d", len(x509Cert.IPAddresses))
	}
}

// ---------------------------------------------------------------------------
// SaveCertificate - certificate with chain (multiple certs)
// ---------------------------------------------------------------------------

func TestSaveCertificateWithInvalidKey(t *testing.T) {
	// Create a cert with an unsupported key type to hit the marshal error in default branch
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "bad-key.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	// Create TLS cert with an invalid private key type (string instead of crypto key)
	// This will trigger the default branch and MarshalPKCS8PrivateKey will fail
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  invalidKeyType{}, // not a valid crypto.Signer
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	err = SaveCertificate(&tlsCert, certFile, keyFile)
	if err == nil {
		t.Error("expected error for invalid key type")
	}
}

// invalidKeyType is a type that satisfies nothing useful for crypto marshaling.
type invalidKeyType struct{}

func (k invalidKeyType) Public() interface{}                     { return nil }
func (k invalidKeyType) Sign(_ io.Reader, _ []byte, _ interface{}) ([]byte, error) { return nil, nil }

func TestSaveCertificateECMarshalError(t *testing.T) {
	// Trigger the MarshalECPrivateKey error by using an ECDSA key with nil Curve.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ec-err.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create cert: %v", err)
	}

	// Create a broken ECDSA key with nil Curve to cause MarshalECPrivateKey to fail
	brokenKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: nil,
			X:     key.X,
			Y:     key.Y,
		},
		D: key.D,
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  brokenKey,
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	err = SaveCertificate(&tlsCert, certFile, keyFile)
	if err == nil {
		t.Error("expected error for ECDSA key with nil curve")
	}
}

func TestSaveCertificateWithChain(t *testing.T) {
	// Create a certificate with an intermediate in the chain
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	serial1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serial2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	root := x509.Certificate{
		SerialNumber: serial1,
		Subject:      pkix.Name{CommonName: "Root CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	leaf := x509.Certificate{
		SerialNumber: serial2,
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, &root, &root, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &leaf, &root, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafDER, rootDER}, // chain with leaf + root
		PrivateKey:  key,
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "chain.pem")
	keyFile := filepath.Join(dir, "key.pem")

	err = SaveCertificate(&tlsCert, certFile, keyFile)
	if err != nil {
		t.Fatalf("SaveCertificate with chain failed: %v", err)
	}

	// Read and verify two CERTIFICATE blocks
	certPEM, _ := os.ReadFile(certFile)
	count := strings.Count(string(certPEM), "BEGIN CERTIFICATE")
	if count != 2 {
		t.Errorf("expected 2 CERTIFICATE blocks, got %d", count)
	}
}
