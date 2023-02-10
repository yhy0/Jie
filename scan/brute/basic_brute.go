package brute

import "github.com/yhy0/Jie/pkg/protocols/httpx"

func Basic_brute(url string) (username string, password string, body string) {
	var basicusers = []string{"admin", "root"}
	if req, err := httpx.RequestBasic("asdasdascsacacs", "adcadcadcadcadcadc", url, "HEAD", "", false, nil); err == nil {
		if req.StatusCode == 401 {
			for useri := range basicusers {
				for passi := range top100pass {
					if req2, err2 := httpx.RequestBasic(basicusers[useri], top100pass[passi], url, "HEAD", "", false, nil); err2 == nil {
						// 403 Forbidden 是HTTP协议中的一个HTTP状态码（Status Code）。403状态码意为服务器成功解析请求但是客户端没有访问该资源的权限
						// 理论上可能存在： https://zhuanlan.zhihu.com/p/270297661
						// 1、成功爆破后，页面跳转（3XX），
						// 2、402 Payment Required（要求付款）
						// 403 Forbidden（被禁止）；
						// 404 Not Found（找不到）
						// 405 Method Not Allowed（不允许的方法）
						// 406 Not Acceptable（不可接受）
						// 407 Proxy Authentication Required（需要代理身份验证）
						// 408 Request Timeout（请求超时）410 Gone（不存在） 409 Conflict（冲突）
						// 400 Bad Request（错误请求）

						if req2.StatusCode != 403 && req2.StatusCode != 401 && req2.StatusCode != 400 && req2.StatusCode != 408 && req2.StatusCode < 405 {
							//pkg.LogJson(rst.Result{PluginName: pkg.GetPluginName("Basic_brute"), StatusCode: req2.StatusCode, URL: url, Technologies: []string{fmt.Sprintf("Found vuln basic password|%s:%s|%s", basicusers[useri], top100pass[passi], url)}})
							return basicusers[useri], top100pass[passi], req.Body
						}
					}
				}
			}
		}
	}
	return "", "", ""
}
