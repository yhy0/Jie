package scan

import "github.com/yhy0/Jie/pkg/task"

/**
  @author: yhy
  @since: 2023/1/11
  @desc: //TODO
**/

type Plugin interface {
	Scan()
}

type PluginInfo struct {
	Target *task.Request
}
