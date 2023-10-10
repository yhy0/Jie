package mitmproxy

/**
  @author: yhy
  @since: 2023/10/10
  @desc: //TODO
**/

import (
	"github.com/lqqyt2423/go-mitmproxy/proxy"
	"github.com/yhy0/logging"
)

func NewMitmproxy() {
	opts := &proxy.Options{
		Debug:             0,
		Addr:              ":9080",
		StreamLargeBodies: 1024 * 1024 * 5,
	}

	p, err := proxy.NewProxy(opts)
	if err != nil {
		logging.Logger.Fatal(err)
	}
	// 添加一个插件用来获取流量信息
	p.AddAddon(&PassiveAddon{})
	logging.Logger.Fatal(p.Start())
}
