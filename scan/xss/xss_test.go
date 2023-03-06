package xss

import (
	"fmt"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"sync"
	"testing"
)

/**
  @author: yhy
  @since: 2023/1/5
  @desc: //TODO
**/

func TestXss(t *testing.T) {
	logging.New(false)
	conf.GlobalConfig = &conf.Config{}
	conf.GlobalConfig.WebScan.Proxy = "http://127.0.0.1:8080"
	httpx.NewSession()

	// 使用 sync.WaitGroup 防止 OutChannel 中的数据没有完全被消费，导致的数据漏掉问题
	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for v := range output.OutChannel {
			fmt.Println(v.PrintScreen())
		}
	}()

	in := &input.CrawlResult{
		Url:    "http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123DalFox",
		Method: "GET",
		Param:  []string{"artist", "asdf", "cat"},
	}

	Scan(in)
	wg.Wait()
}
