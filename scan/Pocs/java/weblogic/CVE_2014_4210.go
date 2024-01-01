package weblogic

import (
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/logging"
)

func CVE_2014_4210(url string, client *httpx.Client) bool {
    if req, err := client.Request(url+"/uddiexplorer/SearchPublicRegistries.jsp", "GET", "", nil); err == nil {
        if req.StatusCode == 200 {
            logging.Logger.Infoln("[Vulnerable] CVE_2014_4210 ", url)
            return true
        }
    }
    logging.Logger.Debugln("[Safety] CVE_2014_4210 ", url)
    return false
}
