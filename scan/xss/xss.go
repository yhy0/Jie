package xss

import (
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/protocols/headless"
	"github.com/yhy0/logging"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: 语义分析、原型链污染、dom 污染点传播分析
**/

func Scan(in *input.CrawlResult) {
	Audit(in)

	if headless.RodHeadless == nil || headless.RodHeadless.Browser == nil {
		logging.Logger.Errorln("browser nil")
		return
	}

	// dom 随主动爬虫检测了，默认就会检测

	// 原型链污染查找 xss
	Prototype(in.Url)
}
