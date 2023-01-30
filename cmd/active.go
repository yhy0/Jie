package cmd

import (
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/task"
	"github.com/yhy0/Jie/pkg/util"
)

/**
  @author: yhy
  @since: 2023/1/11
  @desc: 爬虫主动扫描数据处理
**/

// Active 调用爬虫扫描, 只会输入一个域名
func Active(in *input.Input) {
	logging.Logger.Debugln("Start active crawler scan")
	activeTask := task.Task{
		Input:  in,
		TaskId: util.UUID(),
	}

	activeTask.Crawler()
}
