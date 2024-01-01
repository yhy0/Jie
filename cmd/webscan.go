package cmd

import (
    "github.com/spf13/cobra"
    "github.com/yhy0/Jie/SCopilot"
    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/crawler"
    "github.com/yhy0/Jie/pkg/mode"
    "github.com/yhy0/Jie/pkg/util"
    "github.com/yhy0/logging"
    "strings"
)

/**
   @author yhy
   @since 2023/8/19
   @desc 处理主动和被动扫描
**/

var (
    plugins   []string
    show      bool
    noPlugins bool
    copilot   bool
)

var webScanCmd = &cobra.Command{
    Use:   "web",
    Short: "Run a web scan task",
    Run: func(cmd *cobra.Command, args []string) {
        if !noPlugins {
            // 如果没有禁用插件，并且没有指定插件，则按照配置文件默认插件
            if plugins != nil && len(plugins) > 0 {
                // 首先全部关闭，然后开启指定的，防止配置文件干扰
                for k := range conf.Plugin {
                    conf.Plugin[k] = false
                }
                for _, plugin := range plugins {
                    conf.Plugin[plugin] = true
                }
            }
        } else { // 禁用插件
            // 全部插件关闭
            for k := range conf.Plugin {
                conf.Plugin[k] = false
            }
        }
        if len(plugins) > 0 {
            logging.Logger.Infoln("Plugins:", strings.Join(plugins, ", "))
        }

        conf.GlobalConfig.WebScan.Poc = Poc
        conf.GlobalConfig.Reverse.Host = host
        conf.GlobalConfig.Reverse.Host = domain

        if conf.GlobalConfig.Passive.WebPort != "" {
            if conf.GlobalConfig.Passive.WebPass == "" {
                conf.GlobalConfig.Passive.WebPass = util.RandStr()
                logging.Logger.Infof("Security Copilot web report authorized:%s/%s", conf.GlobalConfig.Passive.WebUser, conf.GlobalConfig.Passive.WebPass)
            }
            go SCopilot.Init()
        }

        if conf.GlobalConfig.Passive.ProxyPort != "" {
            // 原型链 xss 检测使用无头浏览器
            crawler.NewCrawlergo(false)
            // 被动扫描
            mode.Passive()
        } else {
            // 初始化爬虫
            crawler.NewCrawlergo(show)
            for _, target := range conf.GlobalConfig.Options.Targets {
                mode.Active(target)
            }

            if copilot { // 阻塞，不退出
                logging.Logger.Infoln("Scan complete. Blocking program, go to the default port 9088 to view detailed scan information")
                select {}
            }
        }
    },
}

func webScanCmdInit() {
    rootCmd.AddCommand(webScanCmd)
    // 设置需要开启的插件
    webScanCmd.Flags().StringSliceVarP(&plugins, "plugin", "p", nil, "Vulnerable Plugin, (example: --plugin xss,csrf,sql,dir ...)")
    webScanCmd.Flags().BoolVar(&noPlugins, "np", false, "not run plugin")

    // 是否显示无头浏览器
    webScanCmd.Flags().BoolVar(&show, "show", false, "specifies whether the show the browser in headless mode")

    // 设置需要开启的 nuclei poc
    webScanCmd.Flags().StringSliceVar(&Poc, "poc", nil, "specify the nuclei poc to run, separated by ','(example: test.yml,./test/*)")

    // 被动监听，收集流量 Security Copilot mode
    webScanCmd.Flags().StringVar(&conf.GlobalConfig.Passive.ProxyPort, "listen", "", "use proxy resource collector, value is proxy addr, (example: 127.0.0.1:9080)")
    webScanCmd.Flags().StringVar(&conf.GlobalConfig.Passive.WebPort, "web", "9088", "Security Copilot web report port, (example: 9088)")
    webScanCmd.Flags().StringVar(&conf.GlobalConfig.Passive.WebUser, "user", "yhy", "Security Copilot web report authorized user, (example: yhy)")
    webScanCmd.Flags().StringVar(&conf.GlobalConfig.Passive.WebPass, "pwd", "", "Security Copilot web report authorized pwd")

    // 是否阻塞，方便查看 security copilot 页面
    webScanCmd.Flags().BoolVar(&copilot, "copilot", false, "Blocking program, go to the default port 9088 to view detailed scan information")

}
