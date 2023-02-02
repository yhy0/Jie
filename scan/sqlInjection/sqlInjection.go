package sqlInjection

import (
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/scan/sqlInjection/gosqlmap"
	"time"
)

/**
  @author: yhy
  @since: 2022/9/16
  @desc: sql注入检测  参考 https://github1s.com/jweny/gosqlmap
**/

func Scan(in *input.CrawlResult) {
	conf := &gosqlmap.ReqConf{
		Url:     in.Url,
		Headers: in.Headers,
		Data:    in.Kv,
		Method:  in.Method,
	}
	// 连接性检查，初始化result
	isConnect, err := gosqlmap.CheckConnect(conf)
	if isConnect == false || err != nil {
		logging.Logger.Debugf("IsConnect err: %v, SQLInjectionScan CheckConnect err: %v", conf, err)
		return
	}
	// 稳定性检查，更新result
	isStability, err := gosqlmap.CheckStability(conf)
	if isStability == false || err != nil {
		logging.Logger.Debugf("IsStability:%v SQLInjectionScan CheckStability err: %v", isStability, err)
		return
	}
	// 启发式sql注入检测
	sqlInfo, err := gosqlmap.HeuristicCheckSqlInjection(conf)
	if err != nil {
		logging.Logger.Errorln("SQLInjectionScan HeuristicCheckSqlInjection err: ", err)
	}

	// 可能存在注入
	if sqlInfo != (gosqlmap.SQLInfo{}) {
		output.OutChannel <- output.VulMessage{
			DataType: "web_vul",
			Plugin:   "SQL Injection",
			VulData: output.VulData{
				CreateTime: time.Now().Format("2006-01-02 15:04:05"),
				Target:     conf.Url,
				Method:     conf.Method,
				Ip:         in.Ip,
				Param:      conf.Data,
				Payload:    sqlInfo.Payload,
				Request:    sqlInfo.Resquest,
				Response:   sqlInfo.Response,
			},
			Level: output.Critical,
		}
	}
}
