package ecdsa_wrapper

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha1"   // For registration side-effect
	_ "crypto/sha256" // For registration side-effect
	_ "crypto/sha512" // For registration side-effect
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
)

func ParseECPublicKey(derBytes []byte) (pub interface{}, err error) {
	var pki publicKeyInfo
	if rest, err := asn1.Unmarshal(derBytes, &pki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}

	algo := getPublicKeyAlgorithmFromOID(pki.Algorithm.Algorithm)
	if algo == Anonymous {
		return nil, errors.New("x509: unknown public key algorithm")
	}

	return parsePublicKey(algo, &pki)
}

// ParseECPrivateKey parses an EC private key in SEC 1, ASN.1 DER form.
//
// This kind of key is commonly encoded in PEM blocks of type "EC PRIVATE KEY".
func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	return parseECPrivateKey(nil, der)
}

// VerifySignature verifies that the passed in signature over data was created by the given PublicKey.
func VerifySignature(pubKey crypto.PublicKey, data []byte, sig DigitallySigned) error {
	hash, _, err := generateHash(sig.Algorithm.Hash, data)
	if err != nil {
		return err
	}

	switch sig.Algorithm.Signature {
	case ECDSA:
		ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("cannot verify ECDSA signature with %T key", pubKey)
		}
		var ecdsaSig dsaSig
		rest, err := asn1.Unmarshal(sig.Signature, &ecdsaSig)
		if err != nil {
			return fmt.Errorf("failed to unmarshal ECDSA signature: %v", err)
		}
		if len(rest) != 0 {
			log.Printf("Garbage following signature %v", rest)
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("ECDSA signature contained zero or negative values")
		}

		if !ecdsa.Verify(ecdsaKey, hash, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("failed to verify ECDSA signature")
		}
	default:
		return fmt.Errorf("unsupported Algorithm.Signature in signature: %v", sig.Algorithm.Hash)
	}
	return nil
}

func Verify(pubPem, data string, sign string) error {
	pubKey, err := PEM2PK(pubPem)
	if err != nil {
		return err
	}
	signBytes, _ := base64.StdEncoding.DecodeString(sign)
	algo := SignatureAndHashAlgorithm{Hash: SHA256, Signature: ECDSA}
	signed := DigitallySigned{Algorithm: algo, Signature: signBytes}

	return VerifySignature(pubKey, []byte(data), signed)
}

// CreateSignature builds a signature over the given data using the specified hash algorithm and private key.
func CreateSignature(priKey crypto.PrivateKey, hashAlgo HashAlgorithm, data []byte) (DigitallySigned, error) {
	var sig DigitallySigned
	sig.Algorithm.Hash = hashAlgo
	hash, _, err := generateHash(sig.Algorithm.Hash, data)
	if err != nil {
		return sig, err
	}

	switch priKey := priKey.(type) {
	case ecdsa.PrivateKey:
		sig.Algorithm.Signature = ECDSA
		var ecdsaSig dsaSig
		ecdsaSig.R, ecdsaSig.S, err = ecdsa.Sign(rand.Reader, &priKey, hash)
		if err != nil {
			return sig, err
		}
		sig.Signature, err = asn1.Marshal(ecdsaSig)
		return sig, err
	default:
		return sig, fmt.Errorf("unsupported private key type %T, %T", priKey, ecdsa.PrivateKey{})
	}
}

func Sign(privatePem string, data string) (string, error) {
	priKey, err := PEM2PriKey(privatePem)
	if err != nil {
		return "", err
	}
	sig, err2 := CreateSignature(priKey, SHA256, []byte(data))
	if err2 != nil || sig.Signature == nil {
		return "", err2
	}
	return base64.StdEncoding.EncodeToString(sig.Signature), nil

}

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(OIDNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(OIDNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(OIDNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(OIDNamedCurveP521):
		return elliptic.P521()
	case oid.Equal(OIDNamedCurveP192):
		return secp192r1()
	}
	return nil
}

func getPublicKeyAlgorithmFromOID(oid asn1.ObjectIdentifier) SignatureAlgorithm {
	switch {
	case oid.Equal(OIDPublicKeyECDSA):
		return ECDSA
	}
	return Anonymous
}

func parsePublicKey(algo SignatureAlgorithm, keyData *publicKeyInfo) (interface{}, error) {
	asn1Data := keyData.PublicKey.RightAlign()
	switch algo {

	case ECDSA:
		paramsData := keyData.Algorithm.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		rest, err := asn1.Unmarshal(paramsData, namedCurveOID)
		if err != nil {
			return nil, errors.New("x509: failed to parse ECDSA parameters as named curve")
		}
		if len(rest) != 0 {
			return nil, errors.New("x509: trailing data after ECDSA parameters")
		}
		namedCurve := namedCurveFromOID(*namedCurveOID)
		if namedCurve == nil {
			return nil, fmt.Errorf("x509: unsupported elliptic curve %v", namedCurveOID)
		}
		x, y := elliptic.Unmarshal(namedCurve, asn1Data)
		if x == nil {
			return nil, errors.New("x509: failed to unmarshal elliptic curve point")
		}
		pub := &ecdsa.PublicKey{
			Curve: namedCurve,
			X:     x,
			Y:     y,
		}
		return pub, nil
	default:
		return nil, errors.New("unsupported algo")
	}
}

func generateHash(algo HashAlgorithm, data []byte) ([]byte, crypto.Hash, error) {
	var hashType crypto.Hash
	switch algo {
	case MD5:
		hashType = crypto.MD5
	case SHA1:
		hashType = crypto.SHA1
	case SHA224:
		hashType = crypto.SHA224
	case SHA256:
		hashType = crypto.SHA256
	case SHA384:
		hashType = crypto.SHA384
	case SHA512:
		hashType = crypto.SHA512
	default:
		return nil, hashType, fmt.Errorf("unsupported Algorithm.Hash in signature: %v", algo)
	}

	hasher := hashType.New()
	if _, err := hasher.Write(data); err != nil {
		return nil, hashType, fmt.Errorf("failed to write to hasher: %v", err)
	}
	return hasher.Sum([]byte{}), hashType, nil
}

// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	var curve elliptic.Curve
	if namedCurveOID != nil {
		curve = namedCurveFromOID(*namedCurveOID)
	} else {
		curve = namedCurveFromOID(privKey.NamedCurveOID)
	}
	if curve == nil {
		return nil, errors.New("x509: unknown elliptic curve")
	}

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}

func PEM2PK(s string) (crypto.PublicKey, error) {
	p, _ := pem.Decode([]byte(s))
	if p == nil {
		return nil, errors.New("no PEM block found in " + s)
	}

	pubKey, err := ParseECPublicKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to ParseECPublicKey: %v", err)
	}
	return pubKey, nil
}

func PEM2PriKey(s string) (crypto.PrivateKey, error) {
	p, _ := pem.Decode([]byte(s))
	if p == nil {
		return nil, errors.New("no PEM block found in " + s)
	}

	ecPrivKey, err := ParseECPrivateKey(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to ParseECPublicKey: %v", err)
	}
	return *ecPrivKey, nil
}
