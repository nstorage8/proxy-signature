package proxy_signature

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestGenerateSignature(t *testing.T) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	d, err := rand.Int(rand.Reader, max)
	if err != nil {
		t.Fatal(err)
	}
	var w int64 = 1
	signature, err := GenerateSignature(d, w)
	if err != nil {
		t.Fatal(err)
	}
	if signature.W != w {
		t.Errorf("Value of W is wrong. Expected value: %d. Actual value: %d", w, signature.W)
	}
	if signature.S == nil {
		t.Error("Value of S must not be nil")
	}
}

func TestCheckIdentityPositive(t *testing.T) {
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var w int64 = 1
	signature, err := GenerateSignature(new(big.Int).SetBytes(priv), w)
	if err != nil {
		t.Fatal(err)
	}

	identityCheck := CheckIdentity(signature, x, y)
	if !identityCheck {
		t.Error("Identity check must be successful")
	}
}

func TestCheckIdentityNegative(t *testing.T) {
	privA, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, xB, yB, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var w int64 = 1
	signature, err := GenerateSignature(new(big.Int).SetBytes(privA), w)
	if err != nil {
		t.Fatal(err)
	}

	identityCheck := CheckIdentity(signature, xB, yB)
	if identityCheck {
		t.Error("Identity check must not be successful")
	}
}

func TestGenerateSigningKey(t *testing.T) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	d, err := rand.Int(rand.Reader, max)
	if err != nil {
		t.Fatal(err)
	}

	var w int64 = 1
	signature, err := GenerateSignature(d, w)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := GenerateSigningKey(d, signature)
	if signingKey == nil {
		t.Error("Signing key must not be nil")
	}
}

func TestSignMessage(t *testing.T) {
	privA, xA, yA, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privB, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var w int64 = 1
	signature, err := GenerateSignature(new(big.Int).SetBytes(privA), w)
	if err != nil {
		t.Fatal(err)
	}
	checkIdentity := CheckIdentity(signature, xA, yA)
	if !checkIdentity {
		t.Error("Identity check is not passed")
	}
	signingKey := GenerateSigningKey(new(big.Int).SetBytes(privB), signature)

	message := []byte("Test message")
	signed := SignMessage(message, signingKey, new(big.Int).SetBytes(privB))
	if signed == nil {
		t.Error("Signed message must not be nil")
	}
}

func TestCheckSignature(t *testing.T) {
	privA, xA, yA, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privB, xB, yB, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var w int64 = 1
	signature, err := GenerateSignature(new(big.Int).SetBytes(privA), w)
	if err != nil {
		t.Fatal(err)
	}
	checkIdentity := CheckIdentity(signature, xA, yA)
	if !checkIdentity {
		t.Error("Identity check is not passed")
	}
	signingKey := GenerateSigningKey(new(big.Int).SetBytes(privB), signature)

	message := []byte("Test message")
	signed := SignMessage(message, signingKey, new(big.Int).SetBytes(privB))
	if signed == nil {
		t.Error("Signed message must not be nil")
	}

	checkSignature := CheckSignature(message, xB, yB, xA, yA, signed, signature.xP, signature.yP, big.NewInt(w))
	if !checkSignature {
		t.Error("Signature check is not passed")
	}
}

func TestCheckSignatureNegative(t *testing.T) {
	privA, xA, yA, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privB, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, xC, yC, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var w int64 = 1
	signature, err := GenerateSignature(new(big.Int).SetBytes(privA), w)
	if err != nil {
		t.Fatal(err)
	}
	checkIdentity := CheckIdentity(signature, xA, yA)
	if !checkIdentity {
		t.Error("Identity check is not passed")
	}
	signingKey := GenerateSigningKey(new(big.Int).SetBytes(privB), signature)

	message := []byte("Test message")
	signed := SignMessage(message, signingKey, new(big.Int).SetBytes(privB))
	if signed == nil {
		t.Error("Signed message must not be nil")
	}

	checkSignature := CheckSignature(message, xC, yC, xA, yA, signed, signature.xP, signature.yP, big.NewInt(w))
	if checkSignature {
		t.Error("Signature check for wrong open key must not be passed")
	}
}

func TestCheckSignatureNegativeText(t *testing.T) {
	privA, xA, yA, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privB, xB, yB, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var w int64 = 1
	signature, err := GenerateSignature(new(big.Int).SetBytes(privA), w)
	if err != nil {
		t.Fatal(err)
	}
	checkIdentity := CheckIdentity(signature, xA, yA)
	if !checkIdentity {
		t.Error("Identity check is not passed")
	}
	signingKey := GenerateSigningKey(new(big.Int).SetBytes(privB), signature)

	message := []byte("Test message")
	wrongMessage := []byte("Wrong test message")
	signed := SignMessage(message, signingKey, new(big.Int).SetBytes(privB))
	if signed == nil {
		t.Error("Signed message must not be nil")
	}

	checkSignature := CheckSignature(wrongMessage, xB, yB, xA, yA, signed, signature.xP, signature.yP, big.NewInt(w))
	if checkSignature {
		t.Error("Signature check for wrong message must not be passed")
	}
}
