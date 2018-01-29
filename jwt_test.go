package jwt

import (
	"io/ioutil"
	"net/http"
	"reflect"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("JWT", func() {

	It("should be possible to create and verify a token using HMAC", func() {
		claims := Claims{"foo": "bar"}
		key := []byte("secret")
		token, err := CreateToken(claims, []byte("secret"))
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())
		reClaims, err := ValidateToken(token, key)
		Expect(err).NotTo(HaveOccurred())
		Expect(reClaims).To(Equal(claims))
	})

	It("should be possible to create and verify a token using RSA", func() {
		claims := Claims{"foo": "bar"}
		pubKey, err := ParsePublicKey(rsaPubKey)
		Expect(err).NotTo(HaveOccurred())
		privKey, err := ParsePrivateKey(rsaPrivKey)
		Expect(err).NotTo(HaveOccurred())
		token, err := CreateToken(claims, privKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())
		reClaims, err := ValidateToken(token, pubKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(reClaims).To(Equal(claims))
	})

	It("should be possible to create and verify a token using ECDSA", func() {
		claims := Claims{"foo": "bar"}
		pubKey, err := ParsePublicKey(ecdsaPubKey)
		Expect(err).NotTo(HaveOccurred())
		privKey, err := ParsePrivateKey(ecdsaPrivKey)
		Expect(err).NotTo(HaveOccurred())
		token, err := CreateToken(claims, privKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())
		reClaims, err := ValidateToken(token, pubKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(reClaims).To(Equal(claims))
	})

	It("should be possible to load a RSA keys from files", func() {
		ioutil.WriteFile("/tmp/rsa-priv.pem", rsaPrivKey, 0644)
		ioutil.WriteFile("/tmp/rsa-pub.pem", rsaPubKey, 0644)
		privKey, err := LoadPrivateKey("/tmp/rsa-priv.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(reflect.TypeOf(privKey).String()).To(Equal("*rsa.PrivateKey"))
		pubKey, err := LoadPublicKey("/tmp/rsa-pub.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(reflect.TypeOf(pubKey).String()).To(Equal("*rsa.PublicKey"))
	})

	It("should be possible to load a ECDSA keys from files", func() {
		ioutil.WriteFile("/tmp/ecdsa-priv.pem", ecdsaPrivKey, 0644)
		ioutil.WriteFile("/tmp/ecdsa-pub.pem", ecdsaPubKey, 0644)
		privKey, err := LoadPrivateKey("/tmp/ecdsa-priv.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(reflect.TypeOf(privKey).String()).To(Equal("*ecdsa.PrivateKey"))
		pubKey, err := LoadPublicKey("/tmp/ecdsa-pub.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(reflect.TypeOf(pubKey).String()).To(Equal("*ecdsa.PublicKey"))
	})

	It("should NOT be possible to load a keys from non-existing files", func() {
		_, err := LoadPrivateKey("/tmp/not-here")
		Expect(err).To(HaveOccurred())
		_, err = LoadPublicKey("/tmp/not-here")
		Expect(err).To(HaveOccurred())
	})

	It("should NOT be possible to load a keys from files containing no key data", func() {
		_, err := LoadPrivateKey("/etc/hosts")
		Expect(err).To(HaveOccurred())
		_, err = LoadPublicKey("/etc/hosts")
		Expect(err).To(HaveOccurred())
	})

	It("should be possible to get a token from a http requests authorization header", func() {
		claims := Claims{"foo": "bar"}
		pubKey, err := ParsePublicKey(rsaPubKey)
		Expect(err).NotTo(HaveOccurred())
		privKey, err := ParsePrivateKey(rsaPrivKey)
		Expect(err).NotTo(HaveOccurred())
		token, err := CreateToken(claims, privKey)
		Expect(err).NotTo(HaveOccurred())
		r, _ := http.NewRequest("GET", "http://foobar.com", nil)
		r.Header.Add("Authorization", "Bearer "+token)
		prefix, reClaims, err := GetClaimsFromRequest(r, pubKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(reClaims).To(Equal(claims))
		Expect(prefix).To(Equal("Bearer"))
	})

	It("should be possible to get a token from a http requests authorization header with Token prefix", func() {
		claims := Claims{"foo": "bar"}
		pubKey, err := ParsePublicKey(rsaPubKey)
		Expect(err).NotTo(HaveOccurred())
		privKey, err := ParsePrivateKey(rsaPrivKey)
		Expect(err).NotTo(HaveOccurred())
		token, err := CreateToken(claims, privKey)
		Expect(err).NotTo(HaveOccurred())
		r, _ := http.NewRequest("GET", "http://foobar.com", nil)
		r.Header.Add("Authorization", "Token "+token)
		prefix, reClaims, err := GetClaimsFromRequest(r, pubKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(reClaims).To(Equal(claims))
		Expect(prefix).To(Equal("Token"))
	})

	It("should be possible to get a token from a http requests get parameter", func() {
		claims := Claims{"foo": "bar"}
		pubKey, err := ParsePublicKey(rsaPubKey)
		Expect(err).NotTo(HaveOccurred())
		privKey, err := ParsePrivateKey(rsaPrivKey)
		Expect(err).NotTo(HaveOccurred())
		token, err := CreateToken(claims, privKey)
		Expect(err).NotTo(HaveOccurred())
		r, _ := http.NewRequest("GET", "http://foobar.com", nil)
		q := r.URL.Query()
		q.Add("token", token)
		r.URL.RawQuery = q.Encode()

		prefix, reClaims, err := GetClaimsFromRequest(r, pubKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(reClaims).To(Equal(claims))
		Expect(prefix).To(Equal("GET"))
	})

	It("should NOT be possible to get a token from a http requests authorization header if the header is malformed", func() {
		claims := Claims{"foo": "bar"}
		pubKey, err := ParsePublicKey(rsaPubKey)
		Expect(err).NotTo(HaveOccurred())
		privKey, err := ParsePrivateKey(rsaPrivKey)
		Expect(err).NotTo(HaveOccurred())
		token, err := CreateToken(claims, privKey)
		Expect(err).NotTo(HaveOccurred())
		r, _ := http.NewRequest("GET", "http://foobar.com", nil)
		r.Header.Add("Authorization", "bearder "+token+" garbage")
		prefix, reClaims, err := GetClaimsFromRequest(r, pubKey)
		Expect(err).To(HaveOccurred())
		Expect(reClaims).To(BeEmpty())
		Expect(prefix).To(BeEmpty())
	})

	It("should NOT be possible to get a token from a http requests authorization header if the token is missing", func() {
		pubKey, err := ParsePublicKey(rsaPubKey)
		Expect(err).NotTo(HaveOccurred())
		r, _ := http.NewRequest("GET", "http://foobar.com", nil)
		prefix, reClaims, err := GetClaimsFromRequest(r, pubKey)
		Expect(err).To(HaveOccurred())
		Expect(reClaims).To(BeEmpty())
		Expect(prefix).To(BeEmpty())
	})

	It("should NOT be possible to create a token with a wrong key type", func() {
		claims := Claims{"foo": "bar"}
		token, err := CreateToken(claims, "no string key supported!")
		Expect(err).To(HaveOccurred())
		Expect(token).To(BeEmpty())
	})

	It("should NOT be possible to validate a token created with RSA with ECDSA key", func() {
		claims := Claims{"foo": "bar"}
		pubKey, err := ParsePublicKey(ecdsaPubKey)
		Expect(err).NotTo(HaveOccurred())
		privKey, err := ParsePrivateKey(rsaPrivKey)
		Expect(err).NotTo(HaveOccurred())
		token, err := CreateToken(claims, privKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())
		claims, err = ValidateToken(token, pubKey)
		Expect(err).To(HaveOccurred())
		Expect(claims).To(BeEmpty())
	})

	It("should NOT be possible to validate a token created with RSA with HMAC key", func() {
		claims := Claims{"foo": "bar"}
		pubKey := []byte("foobar")
		privKey, err := ParsePrivateKey(rsaPrivKey)
		Expect(err).NotTo(HaveOccurred())
		token, err := CreateToken(claims, privKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())
		claims, err = ValidateToken(token, pubKey)
		Expect(err).To(HaveOccurred())
		Expect(claims).To(BeEmpty())
	})

	It("should NOT be possible to validate a token created with ECDSA with RSA key", func() {
		claims := Claims{"foo": "bar"}
		pubKey, err := ParsePublicKey(rsaPubKey)
		Expect(err).NotTo(HaveOccurred())
		privKey, err := ParsePrivateKey(ecdsaPrivKey)
		Expect(err).NotTo(HaveOccurred())
		token, err := CreateToken(claims, privKey)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())
		claims, err = ValidateToken(token, pubKey)
		Expect(err).To(HaveOccurred())
		Expect(claims).To(BeEmpty())
	})

})

var (
	rsaPubKey = []byte(`-----BEGIN CERTIFICATE-----
MIIDAjCCAeqgAwIBAgIQZHmQHgRA7aLON9rpBmJ+XzANBgkqhkiG9w0BAQsFADAi
MRAwDgYDVQQKEwdBY21lIENvMQ4wDAYDVQQDEwUuL3BraTAeFw0xODAxMDMwNzM4
NThaFw0yODAxMDEwNzM4NThaMCIxEDAOBgNVBAoTB0FjbWUgQ28xDjAMBgNVBAMT
BS4vcGtpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsgOTJIJagCXA
TQQWF/EGOKRqwWhrQ+Cm0dlWz6MCoEGaBV2qi9THaBhdIk537tEy8yADeD9XFJP8
dcnYdSZakUmJMVBvafFcy6o6WFrh/YT/a9ScqQkQ7lPQAlO7wQSCH9ijmo/iECZN
bXbt6+IHhccvENxT/hDycC+iX4cQKyiyBRGOjFeSXezzGiRagyGntRnAbEgvveL+
5t5bp0uVsOSWPq0zKPElpLy0P1D2vxTsbxVUD+pJMbCcyhAODT+miYJ9DcpwE9bM
nME6sG5uCRoZzWjpA6KwV9IxVvwj6F0eoYcCDVhGLqg+5OWuKE+xSbNd9l3m/w9x
ZdZjzbXERwIDAQABozQwMjAOBgNVHQ8BAf8EBAMCAqQwDwYDVR0lBAgwBgYEVR0l
ADAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCUDQNiNR07A7zH
WbT7xfJreMGY4xlPFR++U+ZwAkW5xajtErWbmoamw/CSrKnLg8QCgbHS6+3KE9Zn
Kq+uvyihRVNnfmmwgW6eJTt5nMD0ajrh+WGtld/I9dsdalDcSMKhUGHOktramn81
unmjnT58rk73eDzO9a6gige1/DqUYEt01K8ZAcxdlWZYuqhEBDVPBQlnvTjO6neK
X5VSiSUyOQS/71Ld1YiolB/eJZjfxgBHQ4M6l/mQF59VA4aXZoJ/C7xXraNSvgMW
MUhc9G4hykOg2I9FISY1ZdIngO6XI04zmFAeB9LzC8IfGtOJ5/3j9K6pus7sEuV7
EmeHJzEi
-----END CERTIFICATE-----
`)
	rsaPrivKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsgOTJIJagCXATQQWF/EGOKRqwWhrQ+Cm0dlWz6MCoEGaBV2q
i9THaBhdIk537tEy8yADeD9XFJP8dcnYdSZakUmJMVBvafFcy6o6WFrh/YT/a9Sc
qQkQ7lPQAlO7wQSCH9ijmo/iECZNbXbt6+IHhccvENxT/hDycC+iX4cQKyiyBRGO
jFeSXezzGiRagyGntRnAbEgvveL+5t5bp0uVsOSWPq0zKPElpLy0P1D2vxTsbxVU
D+pJMbCcyhAODT+miYJ9DcpwE9bMnME6sG5uCRoZzWjpA6KwV9IxVvwj6F0eoYcC
DVhGLqg+5OWuKE+xSbNd9l3m/w9xZdZjzbXERwIDAQABAoIBAEgwfO5UUoEfThGt
c4w3+Q7lVkmin8VCCESXf8XqVDlLATvl1TCplEgZgUNVUPuvKJtBw0ZzYUv+C2Z0
+Wvgpt++U32FIflzoO8S1GBaUsUttysyaGmAPLZ5lKQs8rn+qwphH0+hw8pKziFz
Fl8PJX/R27tZrlIc60QlfRKCQkNNqtZhvaLRZ3vFQryb1X045JoYoUFPiHYOt7cj
widP0Ik1/f446yypqlJr7Ha0RBtJ2tKI9uLaOInGeRq38Ha9vLcyGGGn6OC9ylY/
4f5XAgIo3zvmZR4yxMWpTCT67P3qQjfbYfE8lQh3ALis+tHqRMcjlC9GwVo6aZyl
NyKPcckCgYEA53L5OCfVKq4n95dl0nJHgNvVkUSsYIWvd3Aqk4Ag7AsvOUPjCjs2
vhJn131jLthLoIeU31ai13rmPsrCRHMVFmTv5TXPo3mbpHUSfkdvXSiX9enLC3ht
3PcbWDEK/KzVb0iq7Ve43mONRQJMvfAiTBv/fsDir2fQwTme6grG45UCgYEAxOWQ
U/W6FkMoOFcr5Y6oOBm0bVKeiaEk+g/EGKZzCEQZLoLMxDTuq4lytF9c+p7NyLx+
xp69piwLoyzdWMzl6xLBKQGURFYfp9dxUUlEam/0ffuppUjvxXlfW+8iDqIJFc5D
WgceBUXZvmiCf++J420jWqPF0tYPWLXHTIeo0WsCgYASTd512XibUoCorRmJZi5P
e5NNVNAJJil1WbKUTbrM0Cmg7sSC56HxsET0Ht98MfDxNifI7fIc9oRFDQYGIc/W
II90YigUtqZfgD7BK+cbx/0UnrPHKXQO2KAZ/m7vAsAyd93EvX5KYDco8QCeuOIN
gN1Y6epDkwNIdMUjn0yRbQKBgQCu2QU/6dikaGLRFWgf5H0xxHHbGyE6KuXBQjrr
gPRqBL8v9GuOWUsQ/W/lCUJyNI+dkPYrv0++vyJedzrg3qPWCsOJfKODw888py8z
9hJRSrYdIlzWMFzsSgoKg+MEh5P1z0M0MVnRaOQiGIC6x6b1VTeuB/1maz0Zk+M1
7MpXnQKBgQC1td6VxD7OIjVhjNknr/q11JrQG/gsoFHuW1LYbYoAbtddLKE29MUi
vK1C9FdWsRyiJtDsBGLcDq+RUYg0kCWOtmLYpqlPbcOY7MueQ/rTSvit+AWR0Tfp
lMSpb5DGvgUIn9NTvBcMThTU+h6Ay9IzyAobLsmXmqNa10zHOyFkqA==
-----END RSA PRIVATE KEY-----
`)
	ecdsaPubKey = []byte(`-----BEGIN CERTIFICATE-----
MIIB7jCCAU+gAwIBAgIBATAKBggqhkjOPQQDBDAiMRAwDgYDVQQKEwdBY21lIENv
MQ4wDAYDVQQDEwUuL3BraTAeFw0xODAxMTgxNDE4NDFaFw0yODAxMTYxNDE4NDFa
MCAxEDAOBgNVBAoTB0FjbWUgQ28xDDAKBgNVBAMTA2lkcDCBmzAQBgcqhkjOPQIB
BgUrgQQAIwOBhgAEAe9Bxk/KLOpB4Xp+cAu7RdMLJfsQdEqDMUzUurzgirNPIHVT
ETdTMdXIzBK/mOaGO5YmT19WUcAgxCnMqdYk6ZYLAGsKmBtlkqLz4MI7FbMXS6wH
nncIDA2xKgqgAIp3EGO905d3F4ezLb4iVALy/CzRscWLaddJphU7ap122572+ap4
ozUwMzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0T
AQH/BAIwADAKBggqhkjOPQQDBAOBjAAwgYgCQgFoxcZWiouAP8aQOY6FLmdcC5ku
V2zUqImvjySvyCojUpvJ+K/djs/H5uOV7kHnKWkTYXJsDbpmKumADiWSUXQb/gJC
Abzmio9Z2sezZ7hKDmmAkKpr8HfnYEOTR7RDzmELXxmE2qVr2K/BP23/JlgcSKo8
4rLrCDTutW51Ufn2R9+xMBOG
-----END CERTIFICATE-----
`)
	ecdsaPrivKey = []byte(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBJesj9eX4t8d2xdL+YqBqTi14heH5FIAP4KIMkfrxLhfm5mVVhPiJ
U29K/3F/gP8722XvwUa4EFCc8afFRyGFi8igBwYFK4EEACOhgYkDgYYABAHvQcZP
yizqQeF6fnALu0XTCyX7EHRKgzFM1Lq84IqzTyB1UxE3UzHVyMwSv5jmhjuWJk9f
VlHAIMQpzKnWJOmWCwBrCpgbZZKi8+DCOxWzF0usB553CAwNsSoKoACKdxBjvdOX
dxeHsy2+IlQC8vws0bHFi2nXSaYVO2qddtue9vmqeA==
-----END EC PRIVATE KEY-----
`)
)
