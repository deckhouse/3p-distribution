package registry

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/docker/distribution/configuration"
	dcontext "github.com/docker/distribution/context"
	"github.com/gorilla/handlers"
)

func proxyHeadersHandler(ctx context.Context, config *configuration.Configuration, h http.Handler) http.Handler {
	l := dcontext.GetLogger(ctx)
	cfg := config.HTTP.RealIP

	if !cfg.Enabled {
		l.Info("Reverse proxy real IP headers support disabled")
		return h
	}

	var filters []func(r *http.Request) bool
	var opts []string

	if cfg.ClientCert.CA != "" {
		certPool := x509.NewCertPool()

		pem, err := os.ReadFile(cfg.ClientCert.CA)
		if err != nil {
			l.
				WithError(err).
				Fatalf(
					"Cannot load reverse proxy real IP headers support client cert validation CA file %v",
					cfg.ClientCert.CA,
				)
			return h
		}

		certPool.AppendCertsFromPEM(pem)

		filters = append(filters, func(r *http.Request) bool {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				return false
			}

			// Only the leaf may decide.
			//
			// The listener asks for a client certificate but does not verify it
			// itself, so r.TLS.PeerCertificates is whatever the peer chose to
			// send. TLS proves possession of the private key for exactly one of
			// them: the leaf, PeerCertificates[0], whose key signed the
			// handshake. Every other element is bytes the peer attached and
			// proves nothing about who is connecting.
			//
			// Deciding on "some element of the chain verifies" therefore lets a
			// peer holding no CA-issued key claim any source address, by
			// presenting a leaf it controls with the public part of any
			// certificate the CA ever issued attached behind it -- the CA's own
			// certificate included.
			leaf := r.TLS.PeerCertificates[0]
			if leaf == nil {
				return false
			}

			// The rest of the chain is still useful, but only as intermediates:
			// each one has to be signed by something that chains to a
			// configured root, which the peer cannot forge. This keeps a client
			// certificate issued by an intermediate CA working when the CA file
			// carries only the root.
			var intermediates *x509.CertPool
			if len(r.TLS.PeerCertificates) > 1 {
				intermediates = x509.NewCertPool()
				for _, cert := range r.TLS.PeerCertificates[1:] {
					if cert != nil {
						intermediates.AddCert(cert)
					}
				}
			}

			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:         certPool,
				Intermediates: intermediates,
				KeyUsages: []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
				},
			}); err != nil {
				return false
			}

			if cfg.ClientCert.CN != "" && leaf.Subject.CommonName != cfg.ClientCert.CN {
				return false
			}

			return true
		})

		opts = append(opts, fmt.Sprintf("clientcert.ca: \"%v\"", cfg.ClientCert.CA))
		if cfg.ClientCert.CN != "" {
			opts = append(opts, fmt.Sprintf("clientcert.cn: \"%v\"", cfg.ClientCert.CN))
		}
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// add port if not set
		if _, _, err := net.SplitHostPort(r.RemoteAddr); err != nil {
			r.RemoteAddr = net.JoinHostPort(r.RemoteAddr, "0")
		}

		h.ServeHTTP(w, r)
	})

	ret := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(filters) > 0 {
			for _, filter := range filters {
				if filter(r) {
					// Use proxy headers
					handlers.ProxyHeaders(next).ServeHTTP(w, r)
					return
				}
			}
		} else {
			// Use proxy headers
			handlers.ProxyHeaders(next).ServeHTTP(w, r)
			return
		}

		// Call the next handler in the chain.
		next.ServeHTTP(w, r)
	})

	opts = append(opts, fmt.Sprintf("filters: %v", len(filters)))
	l.Infof("Reverse proxy real IP headers support enabled (%v)", strings.Join(opts, ", "))

	return ret
}
