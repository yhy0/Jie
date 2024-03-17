package portScan

import (
    "context"
    "github.com/projectdiscovery/goflags"
    "github.com/projectdiscovery/naabu/v2/pkg/result"
    "github.com/projectdiscovery/naabu/v2/pkg/runner"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/lib/fingerprintx"
    "github.com/yhy0/Jie/pkg/input"
    "github.com/yhy0/Jie/pkg/output"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/scan/gadget/brute"
    "github.com/yhy0/logging"
    "strconv"
    "sync"
)

/**
  @author: yhy
  @since: 2023/10/30
  @desc: //TODO
**/

type Plugin struct {
    SeenRequests sync.Map
}

var lock sync.Mutex

func (p *Plugin) Scan(target string, path string, in *input.CrawlResult, client *httpx.Client) {
    if in.Cdn {
        return
    }
    if p.IsScanned(in.UniqueId) || in.Ip == "" {
        return
    }
    
    res := Scan(target, in.Ip)
    lock.Lock()
    output.IPInfoList[in.Ip].PortService = res
    lock.Unlock()
}

func (p *Plugin) IsScanned(key string) bool {
    if key == "" {
        return false
    }
    if _, ok := p.SeenRequests.Load(key); ok {
        return true
    }
    p.SeenRequests.Store(key, true)
    return false
}

func (p *Plugin) Name() string {
    return "portScan"
}

func Scan(target, ip string) map[string]string {
    var lock sync.Mutex
    
    portService := make(map[string]string)
    options := runner.Options{
        Host:     goflags.StringSlice{ip},
        ScanType: "s", // 扫描类型 s:SynScan c:ConnectScan
        OnResult: func(hr *result.HostResult) {
            if len(hr.Ports) > 30 {
                return
            }
            for _, p := range hr.Ports {
                lock.Lock()
                service := fingerprintx.Scan(ip, p.Port)
                portService[strconv.Itoa(p.Port)] = service
                // 开启服务爆破
                if conf.GlobalConfig.Plugins.BruteForce.Service {
                    go brute.Hydra(target, ip, service, p.Port)
                }
                lock.Unlock()
            }
        },
        Rate: 500,
        // Ports: "",
        TopPorts: "1000", // 扫描 top1000
    }
    
    naabuRunner, err := runner.NewRunner(&options)
    if err != nil {
        logging.Logger.Errorln(err)
        return portService
    }
    defer naabuRunner.Close()
    
    naabuRunner.RunEnumeration(context.Background())
    
    logging.Logger.Println(portService)
    
    return portService
}
