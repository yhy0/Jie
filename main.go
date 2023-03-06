package main

import (
	"github.com/logrusorgru/aurora"
	"github.com/yhy0/Jie/cmd"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/output"
	"sync"
)

/**
  @author: yhy
  @since: 2023/1/27
  @desc: //TODO
**/

func main() {
	// 使用 sync.WaitGroup 防止 OutChannel 中的数据没有完全被消费，导致的数据漏掉问题
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for v := range output.OutChannel {
			logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
		}
	}()

	cmd.RunApp()

	wg.Wait()
}
