package hydra

import (
    "fmt"
    "golang.org/x/crypto/ssh"
    "net"
    "strings"
    "time"
)

/**
  @author: yhy
  @since: 2022/7/3
  @desc: //TODO
**/

func SSH(host string, port int) (string, error) {
    var err error
    var flag bool
    for _, user := range UserDict["ssh"] {
        for _, pass := range Passwords {
            pass = strings.Replace(pass, "{user}", user, -1)
            flag, err = SshConn(host, port, user, pass)
            if flag == true && err == nil {
                return fmt.Sprintf("[%s:%s]", user, pass), nil
            }
            if CheckErrs(err) {
                return "", err
            }
        }
    }
    return "", err
}

func SshConn(host string, port int, user string, pass string) (flag bool, err error) {
    config := &ssh.ClientConfig{
        User:    user,
        Auth:    []ssh.AuthMethod{ssh.Password(pass)},
        Timeout: 3 * time.Second,
        HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
            return nil
        },
    }

    client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", host, port), config)
    if err == nil {
        defer client.Close()
        session, err := client.NewSession()
        if err == nil {
            defer session.Close()

            return true, nil

        }
    }
    return false, err

}
