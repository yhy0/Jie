package hydra

import (
    "database/sql"
    "fmt"
    _ "github.com/denisenkom/go-mssqldb"
    "strings"
    "time"
)

/**
  @author: yhy
  @since: 2022/7/3
  @desc: //TODO
**/

func SQLServer(host string, port int) (string, error) {
    var err error
    var flag bool
    for _, user := range UserDict["mssql"] {
        for _, pass := range Passwords {
            pass = strings.Replace(pass, "{user}", user, -1)
            flag, err = SQLServerConn(host, port, user, pass)
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

func SQLServerConn(host string, port int, user string, pass string) (flag bool, err error) {
    dataSourceName := fmt.Sprintf("server=%s;user id=%s;password=%s;port=%v;encrypt=disable;timeout=%v", host, user, pass, port, 3*time.Second)
    db, err := sql.Open("mssql", dataSourceName)
    if err == nil {
        db.SetConnMaxLifetime(3 * time.Second)
        db.SetConnMaxIdleTime(3 * time.Second)
        db.SetMaxIdleConns(0)
        defer db.Close()
        err = db.Ping()
        if err == nil {
            return true, nil
        }
    }
    return false, err
}
