//go:build darwin

package keychain

import (
	"crypto/x509"
	"fmt"
)

// TrustPolicy selects which SecPolicy is used with SecTrust.
type TrustPolicy int

const (
	// TrustPolicyBasicX509 uses SecPolicyCreateBasicX509 (generic PKIX path validation).
	TrustPolicyBasicX509 TrustPolicy = iota
	// TrustPolicySSLClient uses SecPolicyCreateSSL(false, nil): TLS client-certificate
	// policy (Extended Key Usage / SSL semantics) without a peer hostname.
	TrustPolicySSLClient
)

// CertificateChainOptions configures [Identity.CertificateChain].
type CertificateChainOptions struct {
	// Policy selects SecPolicyCreateBasicX509 vs SecPolicyCreateSSL. The zero
	// value is [TrustPolicyBasicX509].
	Policy TrustPolicy

	// NetworkFetchAllowed sets SecTrustSetNetworkFetchAllowed (e.g. AIA
	// fetching). When nil, this defaults to true.
	NetworkFetchAllowed *bool

	// AnchorCertificates are optional DER-encoded X.509 certificates used as
	// trust anchors when building the chain (e.g. private intermediate/roots
	// not in the system store). Passed to SecTrustSetAnchorCertificates.
	AnchorCertificates [][]byte

	// AnchorCertificatesOnly sets SecTrustSetAnchorCertificatesOnly. When true
	// and AnchorCertificates is non-empty, only those anchors are used.
	AnchorCertificatesOnly bool
}

// CertificateChain evaluates a path for this identity’s leaf certificate using
// SecTrust and returns the ordered chain from SecTrustCopyCertificateChain as
// parsed X.509 certificates (leaf first, then intermediates, then root if
// present).
//
// Use [TrustPolicyBasicX509] for plain PKIX chain building, or
// [TrustPolicySSLClient] when you want TLS client-certificate policy checks.
func (i *Identity) CertificateChain(opts *CertificateChainOptions) ([]*x509.Certificate, error) {
	cf, err := getCoreFoundation()
	if err != nil {
		return nil, err
	}
	sec, err := getSecurity()
	if err != nil {
		return nil, err
	}

	if i.identityRef == 0 {
		return nil, fmt.Errorf("no identity ref")
	}

	var leafRef _SecCertificateRef
	if err := sec.newError(sec.IdentityCopyCertificate(i.identityRef, &leafRef)); err != nil {
		return nil, fmt.Errorf("identity certificate: %w", err)
	}
	defer cf.Release(_CFTypeRef(leafRef))

	certsArr := cf.ArrayOfRefs([]_CFTypeRef{_CFTypeRef(leafRef)})
	defer cf.Release(_CFTypeRef(certsArr))

	policy, err := trustPolicyRef(sec, opts)
	if err != nil {
		return nil, err
	}
	defer cf.Release(_CFTypeRef(policy))

	policiesArr := cf.ArrayOfRefs([]_CFTypeRef{_CFTypeRef(policy)})
	defer cf.Release(_CFTypeRef(policiesArr))

	var trust _SecTrustRef
	if err := sec.newError(sec.TrustCreateWithCertificates(certsArr, policiesArr, &trust)); err != nil {
		return nil, fmt.Errorf("SecTrustCreateWithCertificates: %w", err)
	}
	defer cf.Release(_CFTypeRef(trust))

	networkFetch := true
	if opts != nil && opts.NetworkFetchAllowed != nil {
		networkFetch = *opts.NetworkFetchAllowed
	}
	sec.TrustSetNetworkFetchAllowed(trust, boolToUint8(networkFetch))

	if opts != nil && len(opts.AnchorCertificates) > 0 {
		anchorArr, err := secCertificatesFromDER(cf, sec, opts.AnchorCertificates)
		if err != nil {
			return nil, err
		}
		defer cf.Release(_CFTypeRef(anchorArr))
		if err := sec.newError(sec.TrustSetAnchorCertificates(trust, anchorArr)); err != nil {
			return nil, fmt.Errorf("SecTrustSetAnchorCertificates: %w", err)
		}
		sec.TrustSetAnchorCertificatesOnly(trust, boolToUint8(opts.AnchorCertificatesOnly))
	}

	var cfErr _CFErrorRef
	ok := sec.TrustEvaluateWithError(trust, &cfErr)
	if cfErr != 0 {
		defer cf.Release(_CFTypeRef(cfErr))
	}
	if !ok {
		msg := trustFailureMessage(cf, cfErr)
		return nil, fmt.Errorf("SecTrustEvaluateWithError: %s", msg)
	}

	chainArr := sec.TrustCopyCertificateChain(trust)
	if chainArr == 0 {
		return nil, fmt.Errorf("SecTrustCopyCertificateChain returned nil")
	}
	defer cf.Release(_CFTypeRef(chainArr))

	refs := cf.GoSliceFromCFArray(chainArr)
	out := make([]*x509.Certificate, 0, len(refs))
	for _, ref := range refs {
		certRef := _SecCertificateRef(ref)
		if certRef == 0 {
			continue
		}
		derData := sec.CertificateCopyData(certRef)
		if derData == 0 {
			continue
		}
		der := cf.BytesFromCFData(derData)
		cf.Release(_CFTypeRef(derData))
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		out = append(out, cert)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no certificates in evaluated chain")
	}

	return out, nil
}

func trustPolicyRef(sec *securityFramework, opts *CertificateChainOptions) (_SecPolicyRef, error) {
	p := TrustPolicyBasicX509
	if opts != nil {
		p = opts.Policy
	}

	switch p {
	case TrustPolicyBasicX509:
		ref := sec.PolicyCreateBasicX509()
		if ref == 0 {
			return 0, fmt.Errorf("SecPolicyCreateBasicX509 returned nil")
		}
		return ref, nil
	case TrustPolicySSLClient:
		// server=false, hostname=NULL
		ref := sec.PolicyCreateSSL(0, 0)
		if ref == 0 {
			return 0, fmt.Errorf("SecPolicyCreateSSL returned nil")
		}
		return ref, nil
	default:
		return 0, fmt.Errorf("unknown TrustPolicy: %d", p)
	}
}

func secCertificatesFromDER(cf *coreFoundation, sec *securityFramework, der [][]byte) (_CFArrayRef, error) {
	refs := make([]_CFTypeRef, 0, len(der))
	for _, d := range der {
		dataRef := cf.BytesToCFData(d)
		certRef := sec.CertificateCreateWithData(kCFAllocatorDefault, dataRef)
		cf.Release(_CFTypeRef(dataRef))
		if certRef == 0 {
			for _, r := range refs {
				cf.Release(r)
			}
			return 0, fmt.Errorf("SecCertificateCreateWithData: invalid certificate DER")
		}
		refs = append(refs, _CFTypeRef(certRef))
	}
	arr := cf.ArrayOfRefs(refs)
	for _, r := range refs {
		cf.Release(r)
	}
	return arr, nil
}

func trustFailureMessage(cf *coreFoundation, errRef _CFErrorRef) string {
	if errRef == 0 {
		return "certificate chain could not be verified"
	}
	desc := cf.ErrorCopyDescription(errRef)
	if desc == 0 {
		return "certificate chain could not be verified"
	}
	defer cf.Release(_CFTypeRef(desc))
	return cf.CFStringToString(desc)
}
