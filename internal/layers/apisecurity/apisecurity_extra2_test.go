package apisecurity

import (
	"testing"
)

// TestLoadPublicKeyFromFile_ReadSuccess covers line 582 of jwt.go:
// the return parsePublicKey(data[:n]) path after openFile and readFile succeed.
func TestLoadPublicKeyFromFile_ReadSuccess(t *testing.T) {
	pemData := []byte("-----BEGIN PUBLIC KEY-----\n" +
		"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MqK8k7f5wlFQgWB8E3B4ONIi18p1NfxBTOFzv7G\n" +
		"-----END PUBLIC KEY-----")

	SetFileOps(
		func(path string) (any, error) { return "fake-file", nil },
		func(any) {},
		func(_ any, p []byte) (int, error) { return copy(p, pemData), nil },
	)
	defer SetFileOps(nil, nil, nil)

	_, err := loadPublicKeyFromFile("test.pem")
	// parsePublicKey will fail because the stub DER parsers always return nil,
	// but line 582 (the return statement itself) is now exercised.
	if err == nil {
		t.Error("expected parse error from stub DER parsers")
	}
}

// TestParsePublicKey_Ed25519Raw covers parsePublicKey with a raw 32-byte Ed25519
// public key embedded in a PEM block.  This also exercises the successful-path
// branches in NewJWTValidator (lines 76 and 85).
func TestParsePublicKey_Ed25519Raw(t *testing.T) {
	// A raw 32-byte Ed25519 public key (all zeros except last byte for visibility).
	rawKey := make([]byte, 32)
	rawKey[31] = 0xAB
	b64 := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAs=" // 31 zeros + 0xAB

	pem := "-----BEGIN PUBLIC KEY-----\n" + b64 + "\n-----END PUBLIC KEY-----"
	key, err := parsePublicKey([]byte(pem))
	if err != nil {
		t.Fatalf("expected valid Ed25519 key, got: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}

	// NewJWTValidator with PEM should now succeed.
	v, err := NewJWTValidator(JWTConfig{
		Enabled:      true,
		PublicKeyPEM: pem,
	})
	if err != nil {
		t.Fatalf("expected NewJWTValidator to succeed with Ed25519 PEM: %v", err)
	}
	if v.publicKey == nil {
		t.Fatal("expected publicKey to be set")
	}

	// NewJWTValidator with file should also succeed when file ops are wired.
	pemData := []byte(pem)
	SetFileOps(
		func(path string) (any, error) { return "fake-file", nil },
		func(any) {},
		func(_ any, p []byte) (int, error) { return copy(p, pemData), nil },
	)
	defer SetFileOps(nil, nil, nil)

	v2, err := NewJWTValidator(JWTConfig{
		Enabled:       true,
		PublicKeyFile: "test.pem",
	})
	if err != nil {
		t.Fatalf("expected NewJWTValidator to succeed with Ed25519 file: %v", err)
	}
	if v2.publicKey == nil {
		t.Fatal("expected publicKey to be set from file")
	}
}
