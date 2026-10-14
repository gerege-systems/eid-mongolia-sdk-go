package pades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/digitorus/timestamp"

	"github.com/gerege-systems/eid-mongolia-sdk-go/pades/internal/eidcrypto"
)

// maxTSASkew — genTime нь локал цагаас үүнээс их зөрвөл token-ийг хүлээн авахгүй (CA MaxTSASkew).
const maxTSASkew = 10 * time.Minute

// nonceReader — TSA nonce-ийн эх (тест тодорхойлогдсон утгаар солино).
var nonceReader io.Reader = rand.Reader

// timestampToken — CA pdfsign.Timestamp-ийн клиент хувилбар: signature-ийн SHA-256-д RFC 3161 token авч
// БАТАЛГААЖУУЛНА (nonce, imprint, TSA гинж roots-д EKU timeStamping-тэй, genTime ±10 мин).
func timestampToken(ctx context.Context, f *fetcher, tsaURL string, signature []byte, roots, inter []*x509.Certificate, now time.Time) ([]byte, *timestamp.Timestamp, error) {
	sum := sha256.Sum256(signature)
	nonce, err := rand.Int(nonceReader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return nil, nil, err
	}
	reqDER, err := (&timestamp.Request{HashAlgorithm: crypto.SHA256, HashedMessage: sum[:], Certificates: true, Nonce: nonce}).Marshal()
	if err != nil {
		return nil, nil, err
	}
	body, err := f.do(ctx, http.MethodPost, tsaURL, "application/timestamp-query", reqDER)
	if err != nil {
		return nil, nil, err
	}
	ts, err := timestamp.ParseResponse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("хариу: %w", err)
	}
	if ts.Nonce == nil || ts.Nonce.Cmp(nonce) != 0 {
		return nil, nil, errors.New("nonce таарахгүй")
	}
	if !bytes.Equal(ts.HashedMessage, sum[:]) || ts.HashAlgorithm != crypto.SHA256 {
		return nil, nil, errors.New("timestamp hash does not match")
	}
	if err := verifyTSAChain(ts, roots, inter); err != nil {
		return nil, nil, fmt.Errorf("TSA cert гинж: %w", err)
	}
	if d := now.Sub(ts.Time); d > maxTSASkew || d < -maxTSASkew {
		return nil, nil, fmt.Errorf("TSA genTime %s локал цагаас %s зөрөв", ts.Time.UTC().Format(time.RFC3339), d.Round(time.Second))
	}
	if len(ts.Certificates) == 0 {
		return nil, nil, errors.New("TSA token-д гэрчилгээ алга")
	}
	return ts.RawToken, ts, nil
}

// verifyTSAChain — CA-ийн verifyTSAChain: token-ийн signer cert-ийг roots-д EKU=timeStamping-тэй anchor-лоно.
func verifyTSAChain(ts *timestamp.Timestamp, roots, inter []*x509.Certificate) error {
	p7, err := pkcs7.Parse(ts.RawToken)
	if err != nil {
		return fmt.Errorf("token parse: %w", err)
	}
	signer := p7.GetOnlySigner()
	if signer == nil {
		return errors.New("signer cert олдсонгүй")
	}
	if !eidcrypto.IsTSASigningCert(signer) {
		return errors.New("signer cert-ийн EKU нь critical {timeStamping} биш (RFC 3161 §2.3)")
	}
	rp, ip := x509.NewCertPool(), x509.NewCertPool()
	for _, r := range roots {
		rp.AddCert(r)
	}
	for _, c := range append(p7.Certificates, inter...) {
		if !c.Equal(signer) {
			ip.AddCert(c)
		}
	}
	_, err = signer.Verify(x509.VerifyOptions{Roots: rp, Intermediates: ip, CurrentTime: ts.Time,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}})
	return err
}
