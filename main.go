package main

import (
	"fmt"
	"github.com/yhy0/Jie/cmd"
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
			fmt.Println(v.PrintScreen())
		}
	}()

	//swagger.SwaggerScan("https://ob.dfzq.com.cn:30338/api/swagger-resources", "")
}
