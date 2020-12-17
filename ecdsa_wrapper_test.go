package ecdsa_wrapper

import (
	"testing"

	"gopkg.in/go-playground/assert.v1"
)

// mtg network-id KBD757YWX3.skadnetwork
// for postback version 2.0 without source-app-id
// version + network id + campaign id + app id + transaction-id + redownload
var testPostbackData = "2.0\u2063KBD757YWX3.skadnetwork\u206359\u20631499436635\u2063e3584a40-70a3-4b8b-929d-c17f9ee3ec16\u2063true"

// p192 sign & verify test
func TestSignAndVerifyP192(t *testing.T) {

	testPubKey := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH7k2gaMBkoV5j0OwWKJp+aJdafuF
j7zJy8qoBqqNL7fowLZDBVcRUrC0dKOFoWVWZw9M8uO9ujA5kObyKXOQ4Q==
-----END PUBLIC KEY-----`

	testPriKey := `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFvoo8qNFh3beE0xZxyqfz0G9iQc+zqLR+1zJmnJhk6/oAoGCCqGSM49
AwEHoUQDQgAEH7k2gaMBkoV5j0OwWKJp+aJdafuFj7zJy8qoBqqNL7fowLZDBVcR
UrC0dKOFoWVWZw9M8uO9ujA5kObyKXOQ4Q==
-----END EC PRIVATE KEY-----`

	sign, err := Sign(testPriKey, testPostbackData)
	assert.Equal(t, err, nil)

	err = Verify(testPubKey, testPostbackData, sign)
	assert.Equal(t, err, nil)
}

// p256 sign & verify test
func TestSignAndVerifyP256(t *testing.T) {

	testPubKey := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEH7k2gaMBkoV5j0OwWKJp+aJdafuF
j7zJy8qoBqqNL7fowLZDBVcRUrC0dKOFoWVWZw9M8uO9ujA5kObyKXOQ4Q==
-----END PUBLIC KEY-----`

	testPriKey := `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFvoo8qNFh3beE0xZxyqfz0G9iQc+zqLR+1zJmnJhk6/oAoGCCqGSM49
AwEHoUQDQgAEH7k2gaMBkoV5j0OwWKJp+aJdafuFj7zJy8qoBqqNL7fowLZDBVcR
UrC0dKOFoWVWZw9M8uO9ujA5kObyKXOQ4Q==
-----END EC PRIVATE KEY-----`

	sign, err := Sign(testPriKey, testPostbackData)
	assert.Equal(t, err, nil)

	err = Verify(testPubKey, testPostbackData, sign)
	assert.Equal(t, err, nil)
}

// Apple SKAdNetwork Postback Signature verification
func TestAppleSignature(t *testing.T) {

	var ApplePubPem = `
-----BEGIN PUBLIC KEY-----
MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEMyHD625uvsmGq4C43cQ9BnfN2xslVT5V1nOmAMP6qaRRUll3PB1JYmgSm+62sosG
-----END PUBLIC KEY-----`

	var appleSign = `MDYCGQDL5TmkKdUBVmmjBy0WnWQuknPSz9UHQXQCGQDrlCxEJVsuRu6adMP1+DtCQjNQ0+osGTw=`

	err := Verify(ApplePubPem, testPostbackData, appleSign)

	assert.Equal(t, err, nil)
}
