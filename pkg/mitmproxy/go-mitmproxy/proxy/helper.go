package proxy

import (
    "encoding/base64"
    "io"
    "net"
    "strings"
    
    log "github.com/sirupsen/logrus"
)

var normalErrMsgs []string = []string{
    "read: connection reset by peer",
    "write: broken pipe",
    "i/o timeout",
    "net/http: TLS handshake timeout",
    "io: read/write on closed pipe",
    "connect: connection refused",
    "connect: connection reset by peer",
    "use of closed network connection",
}

// 仅打印预料之外的错误信息
func logErr(log *log.Entry, err error) (loged bool) {
    msg := err.Error()
    
    for _, str := range normalErrMsgs {
        if strings.Contains(msg, str) {
            log.Debug(err)
            return
        }
    }
    
    log.Error(err)
    loged = true
    return
}

// 转发流量
func transfer(log *log.Entry, server, client io.ReadWriteCloser) {
    done := make(chan struct{})
    defer close(done)
    
    errChan := make(chan error)
    go func() {
        _, err := io.Copy(server, client)
        log.Debugln("client copy end", err)
        client.Close()
        select {
        case <-done:
            return
        case errChan <- err:
            return
        }
    }()
    go func() {
        _, err := io.Copy(client, server)
        log.Debugln("server copy end", err)
        server.Close()
        
        if clientConn, ok := client.(*wrapClientConn); ok {
            err := clientConn.Conn.(*net.TCPConn).CloseRead()
            log.Debugln("clientConn.Conn.(*net.TCPConn).CloseRead()", err)
        }
        
        select {
        case <-done:
            return
        case errChan <- err:
            return
        }
    }()
    
    for i := 0; i < 2; i++ {
        if err := <-errChan; err != nil {
            logErr(log, err)
            return // 如果有错误，直接返回
        }
    }
}

// ParseBasicAuth parses an HTTP Basic Authentication string.
// "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" returns ("Aladdin", "open sesame", true).
func ParseBasicAuth(auth string) (username, password string, ok bool) {
    const prefix = "Basic "
    // Case insensitive prefix match. See Issue 22736.
    if len(auth) < len(prefix) || !EqualFold(auth[:len(prefix)], prefix) {
        return "", "", false
    }
    c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
    if err != nil {
        return "", "", false
    }
    cs := string(c)
    username, password, ok = strings.Cut(cs, ":")
    if !ok {
        return "", "", false
    }
    return username, password, true
}

// EqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func EqualFold(s, t string) bool {
    if len(s) != len(t) {
        return false
    }
    for i := 0; i < len(s); i++ {
        if lower(s[i]) != lower(t[i]) {
            return false
        }
    }
    return true
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
    if 'A' <= b && b <= 'Z' {
        return b + ('a' - 'A')
    }
    return b
}
