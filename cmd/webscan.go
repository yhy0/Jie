package cmd

import (
	"github.com/spf13/cobra"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/crawler"
	"github.com/yhy0/Jie/pkg/task"
	"github.com/yhy0/Jie/pkg/util"
	"sync"
	"time"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var webScanCmd = &cobra.Command{
	Use:   "webscan",
	Short: "Run a webscan task",
	Run: func(cmd *cobra.Command, args []string) {
		// 定时器每 24 小时清空记录
		go func() {
			for {
				time.Sleep(24 * time.Hour)
				conf.Visited = &sync.Map{}
			}
		}()

		var plugins []string
		if len(Plugins) == 0 {
			plugins = conf.DefaultPlugins
		} else {
			plugins = util.ToUpper(Plugins)
		}

		conf.GlobalConfig.WebScan.Plugins = plugins
		conf.GlobalConfig.WebScan.Poc = Poc
		conf.GlobalConfig.Reverse.Host = host
		conf.GlobalConfig.Reverse.Host = domain
		conf.GlobalConfig.Debug = false

		if Listen != "" {
			// 被动扫描
			task.Passive()
		} else {
			// 初始化爬虫
			crawler.NewCrawlergo(false)
			for _, target := range conf.GlobalConfig.Options.Targets {
				task.Active(target)
			}
		}
	},
}

func webScanCmdInit() {
	rootCmd.AddCommand(webScanCmd)
	// 设置需要开启的插件
	webScanCmd.Flags().StringSliceVarP(&Plugins, "plugin", "p", conf.DefaultPlugins, "Vulnerable Plugin, (example: --plugin xss,csrf,sql,bbscan ...)")
	// 是否显示无头浏览器
	webScanCmd.Flags().BoolVar(&show, "show", false, "specifies whether the show the browser in headless mode")

	// 设置需要开启的 nuclei poc
	webScanCmd.Flags().StringSliceVar(&Poc, "poc", nil, "specify the nuclei poc to run, separated by ','(example: test.yml,./test/*)")

	// 被动监听，收集流量
	webScanCmd.Flags().StringVar(&Listen, "listen", "", "use proxy resource collector, value is proxy addr, (example: 127.0.0.1:1111)")
}
