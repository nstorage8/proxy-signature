package proxy_signature

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

var curve = elliptic.P256()

type Signature struct {
	xP, yP *big.Int
	S      *big.Int
	W      int64
}

// Generates proxy signature for private key d with given permissions w
func GenerateSignature(d *big.Int, w int64) (*Signature, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))

	k, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	signature := new(Signature)
	xP, yP := curve.ScalarBaseMult(k.Bytes())
	signature.xP = xP
	signature.yP = yP

	// s = d + k*w*r
	s := new(big.Int)
	s.Add(s, d)
	mul := new(big.Int)
	mul.Mul(k, big.NewInt(w))
	mul.Mul(mul, xP)
	s.Add(s, mul)
	signature.S = s
	signature.W = w
	return signature, nil
}

// Checks identification condition for given signature and public key coordinates xH and yH
func CheckIdentity(signature *Signature, xH, yH *big.Int) bool {
	xS, yS := curve.ScalarBaseMult(signature.S.Bytes())
	mul := new(big.Int)
	mul.Mul(big.NewInt(signature.W), signature.xP)
	xP, yP := curve.ScalarMult(signature.xP, signature.yP, mul.Bytes())
	xR, yR := curve.Add(xH, yH, xP, yP)
	return xS.Cmp(xR) == 0 && yS.Cmp(yR) == 0
}

// Generates proxy signing key for proxi signer private key d and given signature
func GenerateSigningKey(d *big.Int, signature *Signature) *big.Int {
	key := new(big.Int)
	key.Add(d, signature.S)
	return key
}

// Returns message signed with proxy signing key l and proxy signer private key d
func SignMessage(message []byte, l, d *big.Int) *big.Int {
	sum256 := new(big.Int)
	bytes := sha256.Sum256(message)
	sum256.SetBytes(bytes[:])
	signed := new(big.Int)
	signed.Mul(l, sum256)
	signed.Add(signed, d)
	return signed
}

// Checks signature validity of given message
func CheckSignature(message []byte, xHb, yHb, xHa, yHa *big.Int, signed *big.Int, xP, yP *big.Int, w *big.Int) bool {
	xS, yS := curve.ScalarBaseMult(signed.Bytes())

	bytes := sha256.Sum256(message)

	mul := new(big.Int)
	mul.Mul(w, xP)
	x1, y1 := curve.ScalarMult(xP, yP, mul.Bytes())
	r1, r2 := curve.Add(xHb, yHb, xHa, yHa)
	r1, r2 = curve.Add(r1, r2, x1, y1)
	r1, r2 = curve.ScalarMult(r1, r2, bytes[:])
	r1, r2 = curve.Add(r1, r2, xHb, yHb)
	return xS.Cmp(r1) == 0 && yS.Cmp(r2) == 0
}
