package swagger

import (
	"fmt"
	"github.com/yhy0/Jie/pkg/output"
	"testing"
)

/**
  @author: yhy
  @since: 2023/1/4
  @desc: //TODO
**/

func TestSwagger(t *testing.T) {
	go func() {
		for v := range output.OutChannel {
			fmt.Println(v.PrintScreen())
		}
	}()

	Scan("", "")
}
