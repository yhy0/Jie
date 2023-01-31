package main

import (
	"github.com/yhy0/Jie/cmd"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/output"
)

/**
  @author: yhy
  @since: 2023/1/27
  @desc: //TODO
**/

func main() {
	cmd.RunApp()
	go func() {
		for v := range output.OutChannel {
			logging.Logger.Println(v.PrintScreen())
		}
	}()
}
