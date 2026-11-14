package kyvernolab

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Media types and annotation keys of cosign's legacy (tag-based) format, the
// one slsa-github-generator v2.1.0 writes and Kyverno's Cosign verifier reads.
const (
	simpleSigningType = "application/vnd.dev.cosign.simplesigning.v1+json"
	dsseType          = "application/vnd.dsse.envelope.v1+json"
	inTotoPayloadType = "application/vnd.in-toto+json"
	annSignature      = "dev.cosignproject.cosign/signature"
	annCertificate    = "dev.sigstore.cosign/certificate"
	annChain          = "dev.sigstore.cosign/chain"
	annPredicateType  = "predicateType"
)

// Fulcio certificate extensions carrying the OIDC issuer.
var (
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// CA stands in for Fulcio: a throwaway root that issues short-lived code
// signing certificates bound to an OIDC issuer and subject URI.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	PEM  string
}

// Identity is a Fulcio-style leaf certificate and its private key.
type Identity struct {
	Subject string
	key     *ecdsa.PrivateKey
	certPEM string
	chain   string
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// NewCA creates a root valid for one hour either side of now.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{Organization: []string{"warden-test"}, CommonName: "warden-test-root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}, nil
}

// Issue returns a leaf with the subject as its URI SAN and the issuer in both
// Fulcio issuer extensions, like a GitHub Actions keyless certificate.
func (ca *CA) Issue(subject, issuer string) (*Identity, error) {
	u, err := url.Parse(subject)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	v2, err := asn1.MarshalWithParams(issuer, "utf8")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: sn, NotBefore: now.Add(-10 * time.Minute), NotAfter: now.Add(50 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs: []*url.URL{u},
		ExtraExtensions: []pkix.Extension{
			{Id: oidIssuerV1, Value: []byte(issuer)},
			{Id: oidIssuerV2, Value: v2},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return &Identity{Subject: subject, key: key,
		certPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), chain: ca.PEM}, nil
}

func (id *Identity) sign(msg []byte) (string, error) {
	sum := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, id.key, sum[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// tagFor maps sha256:<hex> to cosign's sha256-<hex>.<suffix> tag.
func tagFor(digest, suffix string) (string, error) {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexPart) != 64 {
		return "", fmt.Errorf("not a sha256 digest: %q", digest)
	}
	return "sha256-" + hexPart + "." + suffix, nil
}

// Sign attaches a cosign simple-signing signature for repo@digest.
func (r *Registry) Sign(repo, digest string, id *Identity) error {
	tag, err := tagFor(digest, "sig")
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"critical": map[string]any{
			"identity": map[string]string{"docker-reference": repo},
			"image":    map[string]string{"docker-manifest-digest": digest},
			"type":     "cosign container image signature",
		},
		"optional": nil,
	})
	if err != nil {
		return err
	}
	sig, err := id.sign(payload)
	if err != nil {
		return err
	}
	return r.appendLayer(repo, tag, simpleSigningType, payload, map[string]string{
		annSignature: sig, annCertificate: id.certPEM, annChain: id.chain})
}

// Attest attaches a DSSE-wrapped in-toto statement about repo@digest.
func (r *Registry) Attest(repo, digest string, id *Identity, predicateType string, predicate any) error {
	tag, err := tagFor(digest, "att")
	if err != nil {
		return err
	}
	statement, err := json.Marshal(map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"predicateType": predicateType,
		"subject": []map[string]any{{"name": repo,
			"digest": map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")}}},
		"predicate": predicate,
	})
	if err != nil {
		return err
	}
	pae := fmt.Sprintf("DSSEv1 %d %s %d %s", len(inTotoPayloadType), inTotoPayloadType, len(statement), statement)
	sig, err := id.sign([]byte(pae))
	if err != nil {
		return err
	}
	envelope, err := json.Marshal(map[string]any{
		"payloadType": inTotoPayloadType,
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []map[string]string{{"keyid": "", "sig": sig}},
	})
	if err != nil {
		return err
	}
	return r.appendLayer(repo, tag, dsseType, envelope, map[string]string{
		annSignature: "", annCertificate: id.certPEM, annChain: id.chain, annPredicateType: predicateType})
}
