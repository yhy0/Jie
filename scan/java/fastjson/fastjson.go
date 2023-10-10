package fastjson

import (
	"fmt"
	"github.com/yhy0/Jie/scan/java/fastjson/Detect"
)

/**
   @author yhy
   @since 2023/9/18
   @desc //TODO
**/

func Scan(target string) {
	results := Detect.DetectVersion(target)

	fmt.Println(results)
}
