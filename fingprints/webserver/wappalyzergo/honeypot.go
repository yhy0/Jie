package wappalyzergo

import (
    "github.com/thoas/go-funk"
    regexp "github.com/wasilibs/go-re2"
    "strings"
)

/**
  @author: yhy
  @since: 2022/8/17
  @desc: 简单蜜罐指纹
**/

// var regexMap map[string][]string
//
// func init() {
//    regexMap = make(map[string][]string)
//
//    /*
//        <script>var a0_0x4bd8=['uxvyC2S','Aw4UAG','nJu2ndu2sufmz0Pt','Aw9U','versu0C','ndmZnJm2n1fxy05OAq','sML5BeG','ELr2Cxy','v2Hvq00','rvvRBfy','yMLUza','DgvZDa','sgPmuuy','mte4mte0BM1yq2T0','Bg9N','yxrO','DgfIBgu','C2nYAxb0','txj5shC','quXuvNO','AhHRuLe','zgL5s1i','mta2nZa1m29ZyLboAq','y29UC3rY','iciV','vgXbC0y','AgLZiIKO','y3jLyxrL','mNW0Fdn8','ic8IicSG','zxHJzxb0','zxjYB3i','DhjSu00','DMjbDhm','Aw5MBW','BvzPt0O','yxbWBhK','DhvYBIb0','rhbWy2e','mteWmJa3muLUvKffBG','zuXpy1C','z3rfvwu','Cgf0Aa','kYGGk1TE','C3jJ','xIHBxIbD','DwDxy1q','m3WWFdv8','icHMDw5J','mJyXmtK0rwXyC0jy','x19WCM90','CMv0DxjU','C0z1y2S','BhbHuwK','vufqvMO','zKrUsxm','l2PXDq','E30Uy29U','BuX2DMu','D2fYBG','ntu5odCYz3DjyuTJ','DwXQwhi','zxj5lM0','tLv6ueK','k1TEif19','txPrtuu','y29UC29S','Dwn0B3i','zfHlCw4','B19F','BgvUz3rO','yxbWzw5K','C3bSAxq','rwXLBwvU','Dg9tDhjP','C3rYDwn0','mxWYFdq','DgLVBIGP'];
//
//    */
//    regexMap["Honeypot"] = []string{`var \w+\s*=\s*\[(.+)\];`}
// }

func Honeypot(body string) bool {
    regex := regexp.MustCompile(`<script>\w+\s*=\s*\[(.+)\];`)
    
    sensitiveStr := regex.FindAllString(body, -1)
    
    for _, i := range sensitiveStr {
        if len(strings.Split(i, "','")) > 30 && strings.Count(i, "0x") > 30 && funk.Contains(body, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=") && funk.Contains(body, "fromCharCode") {
            return true
        }
    }
    return false
}
