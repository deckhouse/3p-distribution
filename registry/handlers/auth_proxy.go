package handlers

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/docker/distribution/configuration"
	dcontext "github.com/docker/distribution/context"
	"gopkg.in/yaml.v2"
)

type authProxyOptions struct {
	Url string `yaml:"url"`
	CA  string `yaml:"ca"`
}

func getAuthProxyOptions(data any) (params authProxyOptions, err error) {
	buf, err := yaml.Marshal(data)
	if err != nil {
		err = fmt.Errorf("cannot marshal data: %w", err)
		return
	}

	err = yaml.Unmarshal(buf, &params)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal data: %w", err)
	}

	return
}

func registerAuthProxy(app *App, config *configuration.Configuration) error {
	l := dcontext.GetLogger(app)
	if config.Auth.Type() != "token" {
		l.Info("Auth type is not token, auth proxy disabled")
		return nil
	}

	params, ok := config.Auth.Parameters()["proxy"]
	if !ok || params == nil {
		l.Info("Auth proxy disabled: config not found")
		return nil
	}

	opts, err := getAuthProxyOptions(params)
	if err != nil {
		return fmt.Errorf("cannot get auth proxy options: %v", err)
	}

	if opts.Url == "" {
		l.Info("Auth proxy disabled: url not set")
		return nil
	}

	remote, err := url.Parse(opts.Url)
	if err != nil {
		return fmt.Errorf("cannot parse auth proxy uri: %w", err)
	}

	proxyOpts := []string{
		fmt.Sprintf("upstream: \"%v\"", remote),
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if opts.CA != "" {
		certPool, err := x509.SystemCertPool()
		if err != nil {
			return fmt.Errorf("cannot load auth proxy system CAs pool: %w", err)
		}

		pem, err := os.ReadFile(opts.CA)
		if err != nil {
			return fmt.Errorf("cannot load auth proxy CA file %v error: %w", opts.CA, err)
		}

		certPool.AppendCertsFromPEM(pem)

		transport.TLSClientConfig.RootCAs = certPool

		proxyOpts = append(proxyOpts, fmt.Sprintf("CA: \"%v\"", opts.CA))
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetXForwarded()

			r.SetURL(remote)
			r.Out.URL.Path = remote.Path

			r.Out.Host = r.In.Host // keep Host header
		},
		Transport: transport,
	}

	app.router.HandleFunc("/auth/token", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	l.Infof("Auth proxy enabled (%v)", strings.Join(proxyOpts, ", "))
	return nil
}
