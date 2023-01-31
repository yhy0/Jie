package pocs_yml

import (
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/scan/pocs_yml/common/check"
	"github.com/yhy0/Jie/scan/pocs_yml/common/output"
	common_structs "github.com/yhy0/Jie/scan/pocs_yml/common/structs"
	nuclei_parse "github.com/yhy0/Jie/scan/pocs_yml/nuclei/parse"
	xray_requests "github.com/yhy0/Jie/scan/pocs_yml/xray/requests"
	xray_structs "github.com/yhy0/Jie/scan/pocs_yml/xray/structs"
)

/**
  @author: yhy
  @since: 2023/1/31
  @desc: https://github.com/WAY29/pocV
**/

func Scan(in *input.Input) {
	// 初始化dnslog平台
	common_structs.InitReversePlatform(in.Reverse.Domain, in.Reverse.Token)
	if common_structs.ReversePlatformType != xray_structs.ReverseType_Ceye {
		logging.Logger.Errorln("No Ceye api, use dnslog.cn")
	}

	// 初始化http客户端
	xray_requests.InitHttpClient(10, in.Proxy, 5)

	// 初始化nuclei options
	nuclei_parse.InitExecuterOptions(100, 5, in.Proxy)

	// 加载poc
	xrayPocs, nucleiPocs := LoadPocs(&in.Poc)
	// 过滤poc
	tags := make([]string, 0)
	xrayPocs, nucleiPocs = FilterPocs(tags, xrayPocs, nucleiPocs)

	// 计算xray的总发包量，初始化缓存
	xrayTotalReqeusts := 0
	totalTargets := 1
	for _, poc := range xrayPocs {
		ruleLens := len(poc.Rules)
		// 额外需要缓存connectionID
		if poc.Transport == "tcp" || poc.Transport == "udp" {
			ruleLens += 1
		}
		xrayTotalReqeusts += totalTargets * ruleLens
	}
	if xrayTotalReqeusts == 0 {
		xrayTotalReqeusts = 1
	}
	xray_requests.InitCache(xrayTotalReqeusts)

	// 初始化输出
	outputChannel, outputWg := output.InitOutput(in)

	// 初始化check
	check.InitCheck(10, 100)

	// check开始
	check.Start([]string{in.Target}, xrayPocs, nucleiPocs, outputChannel)
	check.Wait()

	// check结束
	close(outputChannel)
	check.End()
	outputWg.Wait()
}
