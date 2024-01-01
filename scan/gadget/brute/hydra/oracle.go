package hydra

import (
    "database/sql"
    "fmt"
    _ "github.com/sijms/go-ora/v2"
    "strings"
    "time"
)

/**
  @author: yhy
  @since: 2022/7/3
  @desc: //TODO
**/

func Oracle(host string, port int) (string, error) {
    var err error
    var flag bool
    for _, user := range UserDict["oracle"] {
        for _, pass := range Passwords {
            pass = strings.Replace(pass, "{user}", user, -1)
            flag, err = OracleConn(host, port, user, pass)
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

func OracleConn(host string, port int, user string, pass string) (flag bool, err error) {
    dataSourceName := fmt.Sprintf("oracle://%s:%s@%s:%s/orcl", user, pass, host, port)
    db, err := sql.Open("oracle", dataSourceName)
    defer db.Close()
    if err == nil {
        db.SetConnMaxLifetime(3 * time.Second)
        db.SetConnMaxIdleTime(3 * time.Second)
        db.SetMaxIdleConns(0)

        err = db.Ping()
        if err == nil {
            return true, nil
        }
    }
    return false, err
}
