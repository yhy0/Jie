package nuclei

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/yhy0/Jie/logging"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
)

var proxyURLList []url.URL

// loadProxyServers load list of proxy servers from file or comma seperated
func loadProxyServers(options *types.Options) error {
	if len(options.Proxy) == 0 {
		return nil
	}
	for _, p := range options.Proxy {
		if proxyURL, err := validateProxyURL(p); err == nil {
			proxyURLList = append(proxyURLList, proxyURL)
		} else if fileutil.FileExists(p) {
			file, err := os.Open(p)
			if err != nil {
				return fmt.Errorf("could not open proxy file: %w", err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				proxy := scanner.Text()
				if strings.TrimSpace(proxy) == "" {
					continue
				}
				if proxyURL, err := validateProxyURL(proxy); err != nil {
					return err
				} else {
					proxyURLList = append(proxyURLList, proxyURL)
				}
			}
		} else {
			return fmt.Errorf("invalid proxy file or URL provided for %s", p)
		}
	}
	return processProxyList(options)
}

func processProxyList(options *types.Options) error {
	if len(proxyURLList) == 0 {
		return fmt.Errorf("could not find any valid proxy")
	} else {
		done := make(chan bool)
		exitCounter := make(chan bool)
		counter := 0
		for _, url1 := range proxyURLList {
			go runProxyConnectivity(url1, options, done, exitCounter)
		}
		for {
			select {
			case <-done:
				{
					close(done)
					return nil
				}
			case <-exitCounter:
				{
					if counter += 1; counter == len(proxyURLList) {
						return errors.New("no reachable proxy found")
					}
				}
			}
		}
	}
}

func runProxyConnectivity(proxyURL url.URL, options *types.Options, done chan bool, exitCounter chan bool) {
	if err := testProxyConnection(proxyURL, options.Timeout); err == nil {
		if types.ProxyURL == "" && types.ProxySocksURL == "" {
			assignProxyURL(proxyURL, options)
			done <- true
		}
	} else {
		logging.Logger.Debugf("Proxy validation failed for '%s': %s", proxyURL.String(), err)
	}
	exitCounter <- true
}

func testProxyConnection(proxyURL url.URL, timeoutDelay int) error {
	timeout := time.Duration(timeoutDelay) * time.Second
	_, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", proxyURL.Hostname(), proxyURL.Port()), timeout)
	if err != nil {
		return err
	}
	return nil
}

func assignProxyURL(proxyURL url.URL, options *types.Options) {
	if options.ProxyInternal {
		os.Setenv(types.HTTP_PROXY_ENV, proxyURL.String())
	}
	if proxyURL.Scheme == types.HTTP || proxyURL.Scheme == types.HTTPS {
		types.ProxyURL = proxyURL.String()
		types.ProxySocksURL = ""
		logging.Logger.Infof("Using %s as proxy server", proxyURL.String())
	} else if proxyURL.Scheme == types.SOCKS5 {
		types.ProxyURL = ""
		types.ProxySocksURL = proxyURL.String()
		logging.Logger.Infof("Using %s as socket proxy server", proxyURL.String())
	}
}

func validateProxyURL(proxy string) (url.URL, error) {
	if url1, err := url.Parse(proxy); err == nil && isSupportedProtocol(url1.Scheme) {
		return *url1, nil
	}
	return url.URL{}, errors.New("invalid proxy format (It should be http[s]/socks5://[username:password@]host:port)")
}

// isSupportedProtocol checks given protocols are supported
func isSupportedProtocol(value string) bool {
	return value == types.HTTP || value == types.HTTPS || value == types.SOCKS5
}
