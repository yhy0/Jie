package hydra

import "strings"

/**
  @author: yhy
  @since: 2023/6/1
  @desc: //TODO
**/

func CheckErrs(err error) bool {
    if err == nil {
        return false
    }
    errs := []string{
        "closed by the remote host", "too many connections",
        "i/o timeout", "EOF", "A connection attempt failed",
        "established connection failed", "connection attempt failed",
        "Unable to read", "is not allowed to connect to this",
        "no pg_hba.conf entry",
        "No connection could be made",
        "invalid packet size",
        "bad connection",
    }
    for _, key := range errs {
        if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(key)) {
            return true
        }
    }
    return false
}
