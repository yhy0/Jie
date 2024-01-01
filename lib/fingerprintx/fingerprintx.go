package fingerprintx

import (
    "fmt"
    "github.com/yhy0/Jie/lib/fingerprintx/pkg/plugins"
    "github.com/yhy0/Jie/lib/fingerprintx/pkg/scan"
    "github.com/yhy0/logging"
    "net/netip"
    "time"
)

/**
  @author: yhy
  @since: 2023/10/30
  @desc: //TODO
**/

// setup the scan config (mirrors command line options)
var fxConfig = scan.Config{
    DefaultTimeout: time.Duration(2) * time.Second,
    FastMode:       false,
    Verbose:        false,
    UDP:            false,
}

func Scan(t string, port int) string {
    // create a target list to scan
    ip, _ := netip.ParseAddr(t)
    target := plugins.Target{
        Address: netip.AddrPortFrom(ip, uint16(port)),
        Host:    t,
    }
    targets := make([]plugins.Target, 1)
    targets = append(targets, target)

    // run the scan
    results, err := scan.ScanTargets(targets, fxConfig)
    if err != nil {
        logging.Logger.Errorln("error: %s\n", err)
        return ""
    }

    // process the results
    for _, result := range results {
        fmt.Printf("%s:%d (%s/%s)\n", result.Host, result.Port, result.Transport, result.Protocol)
    }

    if len(results) > 0 {
        return fmt.Sprintf("%s/%s", results[0].Transport, results[0].Protocol)
    }

    return ""
}
