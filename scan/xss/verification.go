package xss

import (
	"context"
	"github.com/go-rod/rod/lib/proto"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/headless"
	"time"
)

/**
  @author: yhy
  @since: 2023/3/14
  @desc: 验证 payload 是否弹窗
**/

func Verification(payload, u string) bool {
	var flag = false
	page := headless.RodHeadless.Browser.MustPage()
	defer page.Close()

	// 绕过无头浏览器检测 https://bot.sannysoft.com
	page.MustEvalOnNewDocument(`;(() => {` + headless.StealthJS + `})();`)

	ctx, cancel := context.WithCancel(context.Background())
	pageWithCancel := page.Context(ctx)

	// 监听弹窗事件
	wait := pageWithCancel.EachEvent(func(e *proto.PageJavascriptDialogOpening) {
		output.OutChannel <- output.VulMessage{
			DataType: "web_vul",
			Plugin:   "XSS",
			VulnData: output.VulnData{
				CreateTime: time.Now().Format("2006-01-02 15:04:05"),
				Target:     u,
				Method:     "GET",
				Payload:    payload,
			},
			Level: output.Medium,
		}
		flag = true
		cancel()
	}, func(e *proto.PageLoadEventFired) (stop bool) { // 没有弹窗事件跳过
		return true
	})

	//wait := page.WaitEvent(&proto.PageLoadEventFired{})
	pageWithCancel.MustNavigate(payload)
	wait()

	return flag
}
