package mode

import (
    "github.com/yhy0/Jie/pkg/mitmproxy"
    "github.com/yhy0/logging"
)

/**
  @author: yhy
  @since: 2023/1/11
  @desc: 被动代理数据处理
**/

func Passive() {
    logging.Logger.Debugln("Start passive traffic monitoring scan")
    mitmproxy.NewMitmproxy()
}
