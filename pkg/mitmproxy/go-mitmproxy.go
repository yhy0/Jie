package mitmproxy

/**
  @author: yhy
  @since: 2023/10/10
  @desc: //TODO
**/

import (
    "github.com/panjf2000/ants/v2"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/pkg/mitmproxy/go-mitmproxy/proxy"
    "github.com/yhy0/Jie/pkg/task"
    "github.com/yhy0/logging"
)

var t *task.Task
var PassiveProxy *proxy.Proxy

func NewMitmproxy() {
    opts := &proxy.Options{
        Username:          conf.GlobalConfig.Mitmproxy.BasicAuth.Username,
        Password:          conf.GlobalConfig.Mitmproxy.BasicAuth.Password,
        Header:            conf.GlobalConfig.Mitmproxy.BasicAuth.Header,
        Debug:             0,
        Addr:              conf.GlobalConfig.Passive.ProxyPort,
        StreamLargeBodies: 1024 * 1024 * 5,
        SslInsecure:       true,
    }
    
    t = &task.Task{
        Parallelism: conf.Parallelism + 1,
        ScanTask:    make(map[string]*task.ScanTask),
    }
    
    pool, _ := ants.NewPool(t.Parallelism)
    t.Pool = pool
    defer t.Pool.Release() // 释放协程池
    
    // 先加一，这里会一直阻塞，这样就不会马上退出, 这里要的就是一直阻塞，所以不使用 wg.Done()
    t.WG.Add(1)
    
    var err error
    PassiveProxy, err = proxy.NewProxy(opts)
    if err != nil {
        logging.Logger.Fatal(err)
    }
    
    // 添加一个插件用来获取流量信息
    PassiveProxy.AddAddon(&PassiveAddon{})
    go func() {
        err = PassiveProxy.Start()
        if err != nil {
            logging.Logger.Fatal(err)
        }
    }()
    
    t.WG.Wait()
}
