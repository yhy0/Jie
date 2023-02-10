package sqlmap

import (
	"github.com/antlabs/strsim"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"math"
	"math/rand"
	"time"
)

/**
  @author: yhy
  @since: 2023/2/10
  @desc: 工具类辅助函数
**/

// getErrorBasedPreCheckPayload 闭合 payload
func getErrorBasedPreCheckPayload() string {
	rand.Seed(time.Now().Unix())
	randomTestString := ""
	for i := 0; i < 10; i++ {
		randomTestString += HeuristicCheckAlphabet[rand.Intn(len(HeuristicCheckAlphabet)-1)]
	}

	return randomTestString
}

// getNormalRespondTime 对目标发起5次请求, 正常的响应时间应该小于等于这个值
func getNormalRespondTime(sql *Sqlmap) (error, float64) {

	var timeRec []float64
	for i := 0; i < 5; i++ {
		res, err := httpx.Request(sql.Url, sql.Method, sql.PostData, false, sql.Headers)
		if err != nil {
			return err, -1
		}

		timeRec = append(timeRec, res.ServerDurationMs)

	}
	// 正常情况下，响应时间的分布是符合正态分布的，而正态分布的 99.99% 的数据都在 7 倍的标准差之内，所以这里就是为了过滤掉 99.99% 的无延迟请求。
	return nil, mean(timeRec) + 7*std(timeRec)

}

// 期望,也就是平均响应时间
func mean(v []float64) float64 {
	var res float64 = 0
	var n = len(v)
	for i := 0; i < n; i++ {
		res += v[i]
	}
	return res / float64(n)
}

// 方差
func variance(v []float64) float64 {
	var res float64 = 0
	var m = mean(v)
	var n = len(v)
	for i := 0; i < n; i++ {
		res += (v[i] - m) * (v[i] - m)
	}
	return res / float64(n-1)
}

// 标准差
func std(v []float64) float64 {
	return math.Sqrt(variance(v))
}

func comparison(respBody string, respCode int, templateBody string, templCode int, defaultRatio float64) (bool, float64) {
	if respCode == templCode {
		ratio := strsim.Compare(respBody, templateBody)
		if defaultRatio == -1 {
			if ratio >= LowerRatioBound && ratio <= UpperRatioBound {
				defaultRatio = ratio
			}
		}

		if ratio > UpperRatioBound {
			return true, defaultRatio
		} else if ratio < LowerRatioBound {
			return false, defaultRatio
		} else {
			return (ratio - defaultRatio) > DiffTolerance, defaultRatio
		}

	}
	return false, defaultRatio
}
