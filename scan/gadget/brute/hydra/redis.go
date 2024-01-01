package hydra

import (
    "errors"
    "fmt"
    "net"
    "strings"
    "time"
)

/**
  @author: yhy
  @since: 2022/7/1
  @desc: //TODO
**/

func Redis(host string, port int) (string, error) {

    err := unauth(host, port)
    if err == nil {
        return "Unauthorized", nil
    }

    for _, pass := range Passwords {
        err = conn(host, port, pass)
        if err == nil {
            return pass, nil
        }

        if CheckErrs(err) {
            return "", err
        }
    }

    return "", err
}

func conn(host string, port int, pass string) error {
    netloc := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", netloc, 5*time.Second)
    if err != nil {
        return err
    }
    defer conn.Close()

    err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    if err != nil {
        return err
    }

    _, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass)))
    time.Sleep(time.Millisecond * 500)
    if err != nil {
        return err
    }
    reply, err := readResponse(conn)
    if err != nil {
        return err
    }

    if strings.Contains(reply, "+OK") {
        return nil
    } else if err == nil {
        return errors.New("authentication failed")
    }
    return err
}

func unauth(host string, port int) error {
    netloc := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", netloc, 5*time.Second)
    if err != nil {
        return err
    }
    defer conn.Close()

    err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    if err != nil {
        return err
    }

    _, err = conn.Write([]byte(fmt.Sprintf("info\r\n")))
    time.Sleep(time.Second * 1)
    if err != nil {
        return err
    }
    reply, err := readResponse(conn)
    if err != nil {
        return err
    }

    // 这里会出现一种 reply 不为空，但需要认证，并且 err 为空的现象

    if strings.Contains(reply, "redis_version") {
        return nil
    } else if err == nil {
        return errors.New("authentication failed")
    }

    return err
}

func readResponse(conn net.Conn) (r string, err error) {
    buf := make([]byte, 4096)
    for {
        count, err := conn.Read(buf)
        if err != nil {
            break
        }
        r += string(buf[0:count])
        if count < 4096 {
            break
        }
    }
    return r, err
}
