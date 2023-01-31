package cmd

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/urfave/cli/v2"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/logging"
	"github.com/yhy0/Jie/pkg/input"
	"github.com/yhy0/Jie/pkg/protocols/http"
	"github.com/yhy0/Jie/pkg/util"
	"os"
)

/**
  @author: yhy
  @since: 2023/1/3
  @desc: //TODO
**/

var (
	DefaultPlugins = []string{"XSS", "SQL", "CMD-INJECT", "XXE", "SSRF", "POC", "BRUTE", "JSONP", "CRLF"}
	Plugins        cli.StringSlice
	Poc            cli.StringSlice
	Proxy          string
	Listen         string
	Target         string
)

func init() {
	fmt.Println("\t" + aurora.Green(conf.Banner).String())
	fmt.Println("\t\t\t" + aurora.Red("v"+conf.Version).String())
	fmt.Println("\t\t" + aurora.Blue(conf.Website).String() + "\n\n")

	fmt.Println(aurora.Red("Use with caution. You are responsible for your actions.").String())
	fmt.Println(aurora.Red("Developers assume no liability and are not responsible for any misuse or damage.").String() + "\n")
}

func RunApp() {
	app := &cli.App{
		Name:  "Jie",
		Usage: "A powerful web security assessment tool",
		Commands: []*cli.Command{
			{
				Name:    "webscan",
				Aliases: []string{"ws"},
				Usage:   "Run a webscan task",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "browser-crawler",
						Aliases:     []string{"browser"},
						Usage:       "use a browser spider to crawl the target and scan the requests",
						Destination: &Target,
						Required:    true,
					},
					// 设置需要开启的插件
					&cli.StringSliceFlag{
						Name:        "plugin",
						Usage:       "Vulnerable Plugin, (example: --plugin xss,csrf,sql, ...)",
						Destination: &Plugins,
					},
					// 设置需要开启的插件
					&cli.StringSliceFlag{
						Name:        "poc",
						Usage:       "specify the poc to run, separated by ','(example: test.yml,./test/*)",
						Destination: &Poc,
					},
					// 设置代理
					&cli.StringFlag{
						Name:        "proxy",
						Usage:       "Proxy, (example: --proxy http://127.0.0.1:8080)",
						Destination: &Proxy,
					},
					// 被动监听，收集流量
					&cli.StringFlag{
						Name:        "listen",
						Usage:       "use proxy resource collector, value is proxy addr, (example: 127.0.0.1:1111)",
						Destination: &Listen,
					},
				},
				Action: func(cCtx *cli.Context) error {
					return nil
				},
			},
			{
				Name:    "generate-ca-cert",
				Aliases: []string{"genca"},
				Usage:   "GenerateToFile CA certificate and key",
				Action: func(cCtx *cli.Context) error {
					fmt.Println("genca : ", cCtx.Args().First())
					return nil
				},
			},
		},
	}
	app.Suggest = true
	if err := app.Run(os.Args); err != nil {
		logging.Logger.Fatal(err)
	}

	var plugins []string
	if len(Plugins.Value()) == 0 {
		plugins = DefaultPlugins
	} else {
		plugins = util.ToUpper(Plugins.Value())
	}

	// 主动扫描
	in := &input.Input{
		Target:  Target,
		Proxy:   Proxy,
		Plugins: plugins,
		Poc:     Poc.Value(),
	}

	// 初始化 session ,todo 后续优化一下，不同网站共用一个不知道会不会出问题，应该不会
	http.NewSession()

	if Listen != "" {
		// 被动扫描
		Passive(in)
	} else {
		// 主动扫描
		Active(in)
	}

}
