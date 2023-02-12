package sqlInjection

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

/**
  @author: yhy
  @since: 2023/2/11
  @desc: //TODO
**/

func TestSqlmap(t *testing.T) {
	//logging.New(true)
	//conf.GlobalConfig = &conf.Config{}
	//conf.GlobalConfig.WebScan.Proxy = "http://127.0.0.1:8080"
	//httpx.NewSession()
	//
	//go func() {
	//	for v := range output.OutChannel {
	//		logging.Logger.Println(v.PrintScreen())
	//	}
	//}()
	//
	//in := &input.CrawlResult{
	//	Url:         "http://testphp.vulnweb.com/listproducts.php?artist=1",
	//	Method:      "GET",
	//	RequestBody: "",
	//	Param:       []string{"artist"},
	//	Headers:     map[string]string{},
	//}
	//
	//response, err := httpx.Request(in.Url, in.Method, in.RequestBody, true, nil)
	//if err != nil {
	//	return
	//}
	//
	//in.Resp = response
	//
	//Scan(in)

	var source = rand.New(rand.NewSource(time.Now().UnixNano()))

	fmt.Println(fmt.Sprintf("%04v", source.Int31n(10000)))
}
