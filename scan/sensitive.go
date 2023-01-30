package scan

import (
	"fmt"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/util"
	"time"

	"regexp"
)

/**
  @author: yhy
  @since: 2022/7/22
  @desc: //TODO
**/

var regexMap map[string][]string

func init() {
	regexMap = make(map[string][]string)

	regexMap["GoogleApi"] = []string{`AIza[0-9A-Za-z-_]{35}`}
	regexMap["Firebase"] = []string{`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`}
	regexMap["GoogleCaptcha"] = []string{`6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`}
	regexMap["GoogleOauth"] = []string{`ya29\.[0-9A-Za-z\-_]+`}
	regexMap["AmazonAwsAccessKeyId"] = []string{`A[SK]IA[0-9A-Z]{16}`}
	regexMap["AmazonMwsAuthToke"] = []string{`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`}
	regexMap["AmazonAwsUrl"] = []string{`s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`}
	regexMap["FacebookAccessToken"] = []string{`EAACEdEose0cBA[0-9A-Za-z]+`}
	regexMap["AuthorizationBasic"] = []string{`basic [a-zA-Z0-9=:_\+\/-]{10,100}`}
	regexMap["AuthorizationBearer"] = []string{`bearer [a-zA-Z0-9_\-\.=:_\+\/]{10,100}`}
	// regexMap["AuthorizationApi"] = []string{`api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`}
	regexMap["MailgunApiKey"] = []string{`key-[0-9a-zA-Z]{32}`}
	//regexMap["TwilioApiKey"] = []string{`SK[0-9a-fA-F]{32}`}
	//regexMap["TwilioAccountSid"] = []string{`AC[a-zA-Z0-9_\-]{32}`}
	//regexMap["TwilioAppSid"] = []string{`AP[a-zA-Z0-9_\-]{32}`}
	regexMap["PaypalBraintreeAccessToken"] = []string{`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`}
	regexMap["SquareOauthSecret"] = []string{`sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`}
	regexMap["SquareAccessToken"] = []string{`sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`}
	regexMap["StripeStandardApi"] = []string{`sk_live_[0-9a-zA-Z]{24}`}
	regexMap["StripeRestrictedApi"] = []string{`rk_live_[0-9a-zA-Z]{24}`}
	regexMap["GithubAccessToken"] = []string{`[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`}
	regexMap["GitHub"] = []string{`[g|G][i|I][t|T][h|H][u|U][b|B].{0,30}['\"\\s][0-9a-zA-Z]{35,40}['\"\\s]`}
	regexMap["RASPrivateKey"] = []string{`-----BEGIN RSA PRIVATE KEY-----`}
	regexMap["SSHDsaPrivateKey"] = []string{`-----BEGIN DSA PRIVATE KEY-----`}
	regexMap["SSHDcPrivateKey"] = []string{`-----BEGIN EC PRIVATE KEY-----`}
	regexMap["PGPPrivateBlock"] = []string{`-----BEGIN PGP PRIVATE KEY BLOCK-----`}
	regexMap["JsonWebToken"] = []string{`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`}
	regexMap["SlackToken"] = []string{`\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"`}
	regexMap["SshPrivkey"] = []string{`([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`}

	//误报过多
	//regexMap["HerokuAPIKEY"] = []string{`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`}

	// 邮箱太多重复，先去除
	//regexMap["Email"] = []string{`[\w\.]+@\w+\.[a-z]{2,3}(\.[a-z]{2,3})?`}
	regexMap["JDBC"] = []string{`jdbc:[a-z:]+://[a-z0-9\.\-_:;=/@?,&]+`}
	regexMap["MicrosoftTeamsWebhook"] = []string{`https://outlook\.office\.com/webhook/[a-z0-9@-]+/IncomingWebhook/[a-z0-9-]+/[a-z0-9-]+`}
	regexMap["ZohoWebhook"] = []string{`https://creator\.zoho\.com/api/[a-z0-9/_.-]+\?authtoken=[a-z0-9]+`}
	regexMap["Ueditor"] = []string{`ueditor\.(config|all)\.js`}
	regexMap["OSS"] = []string{`[A|a]ccess[K|k]ey[I|i][d|D]|[A|a]ccess[K|k]ey[S|s]ecret`}
}

// Detection 页面敏感信息检测
func Detection(url, resStr, assets, uuid, cuuid, user string) {
	sensitive := make(map[string][]string)
	for k, vs := range regexMap {
		for _, value := range vs {
			regex := regexp.MustCompile(value)

			sensitiveStr := util.RemoveDuplicateElement(regex.FindAllString(resStr, -1))

			if len(sensitiveStr) > 0 {
				if sensitive[k] != nil {
					sensitive[k] = append(sensitive[k], sensitiveStr...)
				} else {
					sensitive[k] = sensitiveStr
				}
			}
		}
	}

	if len(sensitive) > 0 {
		output.OutChannel <- output.VulMessage{
			DataType: "web_vul",
			Plugin:   "Sensitive",
			VulData: output.VulData{
				CreateTime: time.Now().Format("2006-01-02 15:04:05"),
				Target:     url,
				Payload:    fmt.Sprintf("%+v", sensitive),
			},
			Level: "Critical",
		}
	}
}
