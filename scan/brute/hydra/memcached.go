package hydra

import (
	"fmt"
	"net"
	"strings"
	"time"
)

/**
  @author: yhy
  @since: 2022/7/3
  @desc: //TODO
**/

func Memcached(host string, port int) (string, error) {
	realhost := fmt.Sprintf("%s:%v", host, port)
	client, err := net.DialTimeout("tcp", realhost, 3*time.Second)
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err == nil {
		err = client.SetDeadline(time.Now().Add(3 * time.Second))
		if err == nil {
			_, err = client.Write([]byte("stats\n")) //Set the key randomly to prevent the key on the server from being overwritten
			if err == nil {
				rev := make([]byte, 1024)
				n, err := client.Read(rev)
				if err == nil {
					if strings.Contains(string(rev[:n]), "STAT") {
						return "Unauthorized", nil
					}
				}
			}
		}
	}
	return "", err
}
