package mitmproxy

import (
    "bytes"
    "fmt"
    "github.com/yhy0/Jie/pkg/mitmproxy/go-mitmproxy/proxy"
    "github.com/yhy0/logging"
    "net/http"
    "strings"
    "unicode"
)

/**
   @author yhy
   @since 2023/10/15
   @desc //TODO
**/

func requestDump(r *proxy.Request) string {
    buf := bytes.NewBuffer(make([]byte, 0))
    fmt.Fprintf(buf, "%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
    fmt.Fprintf(buf, "Host: %s\r\n", r.URL.Host)
    if len(r.Raw().TransferEncoding) > 0 {
        fmt.Fprintf(buf, "Transfer-Encoding: %s\r\n", strings.Join(r.Raw().TransferEncoding, ","))
    }
    if r.Raw().Close {
        fmt.Fprintf(buf, "Connection: close\r\n")
    }

    err := r.Header.WriteSubset(buf, nil)
    if err != nil {
        logging.Logger.Error(err)
    }
    buf.WriteString("\r\n")

    if r.Body != nil && len(r.Body) > 0 && canPrint(r.Body) {
        buf.Write(r.Body)
        buf.WriteString("\r\n\r\n")
    }

    return buf.String()
}

func responseDump(f *proxy.Flow) string {
    buf := bytes.NewBuffer(make([]byte, 0))
    if f.Response != nil {
        fmt.Fprintf(buf, "%v %v %v\r\n", f.Request.Proto, f.Response.StatusCode, http.StatusText(f.Response.StatusCode))
        err := f.Response.Header.WriteSubset(buf, nil)
        if err != nil {
            logging.Logger.Error(err)
        }
        buf.WriteString("\r\n")
        if f.Response.Body != nil && len(f.Response.Body) > 0 {
            body, err := f.Response.DecodedBody()
            if err == nil && body != nil && len(body) > 0 {
                buf.Write(body)
                buf.WriteString("\r\n\r\n")
            }
        }
    }
    return buf.String()
}

func canPrint(content []byte) bool {
    for _, c := range string(content) {
        if !unicode.IsPrint(c) && !unicode.IsSpace(c) {
            return false
        }
    }
    return true
}
