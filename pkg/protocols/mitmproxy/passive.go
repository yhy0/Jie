package mitmproxy

import (
	"bytes"
	"fmt"
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/yhy0/logging"
	"strings"
)

/**
  @author: yhy
  @since: 2023/10/10
  @desc: go-mitmproxy 插件，用来获取流量信息
**/

type PassiveAddon struct {
	proxy.BaseAddon
	done chan bool
}

// Requestheaders HTTP请求头已成功读取。此时，请求体为空。
func (pa *PassiveAddon) Requestheaders(f *proxy.Flow) {
	logging.Logger.Printf("Host: %v, Method: %v, Scheme: %v", f.Request.URL.Host, f.Request.Method, f.Request.URL.Scheme)
	f.Request.URL.Host = "www.baidu.com"
	f.Request.URL.Scheme = "http"
	logging.Logger.Printf("After: %v", f.Request.URL)
}

// Request 完整的HTTP请求已被读取
func (pa *PassiveAddon) Request(f *proxy.Flow) {
	buf := bytes.NewBuffer(make([]byte, 0))
	fmt.Fprintf(buf, "%s %s %s\r\n", f.Request.Method, f.Request.URL.RequestURI(), f.Request.Proto)
	fmt.Fprintf(buf, "Host: %s\r\n", f.Request.URL.Host)
	if len(f.Request.Raw().TransferEncoding) > 0 {
		fmt.Fprintf(buf, "Transfer-Encoding: %s\r\n", strings.Join(f.Request.Raw().TransferEncoding, ","))
	}
	if f.Request.Raw().Close {
		fmt.Fprintf(buf, "Connection: close\r\n")
	}

	err := f.Request.Header.WriteSubset(buf, nil)
	if err != nil {
		logging.Logger.Error(err)
	}
	buf.WriteString("\r\n")

	if f.Request.Body != nil && len(f.Request.Body) > 0 {
		buf.Write(f.Request.Body)
		buf.WriteString("\r\n\r\n")
	}

	logging.Logger.Errorln(buf.String())
}
