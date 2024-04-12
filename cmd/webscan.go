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
    plugins    []string
    show       bool
    craw       string
    noPlugins  bool
    allPlugins bool
    copilot    bool
)

var webScanCmd = &cobra.Command{
    Use:   "web",
    Short: "Run a web scan task",
    Run: func(cmd *cobra.Command, args []string) {
        if !noPlugins {
            // 如果没有禁用插件，并且没有指定插件，则按照配置文件默认插件
            if plugins != nil {
                if len(plugins) == 1 && plugins[0] == "all" {
                    // 插件全部开启
                    for k := range conf.Plugin {
                        conf.Plugin[k] = true
                    }
                    logging.Logger.Infoln("Scan plugins are all on")
                } else {
                    // 首先全部关闭，然后开启指定的，防止配置文件干扰
                    for k := range conf.Plugin {
                        conf.Plugin[k] = false
                    }
                    for _, plugin := range plugins {
                        conf.Plugin[plugin] = true
                    }
                    
                    logging.Logger.Infoln("Plugins:", strings.Join(plugins, ", "))
                }
            }
        } else { // 禁用插件
            // 全部插件关闭
            for k := range conf.Plugin {
                conf.Plugin[k] = false
            }
        }
        
        conf.GlobalConfig.WebScan.Poc = Poc
        conf.GlobalConfig.WebScan.Show = show
        conf.GlobalConfig.WebScan.Craw = craw
        conf.GlobalConfig.Reverse.Host = host
        conf.GlobalConfig.Reverse.Host = domain
        
        if conf.GlobalConfig.Passive.WebPort != "" {
            if conf.GlobalConfig.Passive.WebPass == "" {
                conf.GlobalConfig.Passive.WebPass = util.RandStr()
                logging.Logger.Infof("Security Copilot web report authorized:%s/%s", conf.GlobalConfig.Passive.WebUser, conf.GlobalConfig.Passive.WebPass)
            }
            go SCopilot.Init()
        }
        conf.Preparations()
        if conf.GlobalConfig.Passive.ProxyPort != "" {
            crawler.NewCrawlergo(false)
            // 被动扫描
            mode.Passive()
        } else {
            // 初始化爬虫
            if conf.GlobalConfig.WebScan.Craw == "c" {
                crawler.NewCrawlergo(show)
            }
            
            for _, target := range conf.GlobalConfig.Options.Targets {
                mode.Active(target, nil)
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
    webScanCmd.Flags().StringSliceVarP(&plugins, "plugin", "p", nil, "Vulnerable Plugin, (example: --plugin xss,csrf,sql,dir ...)\r\n指定开启的插件，当指定 all 时开启全部插件")
    webScanCmd.Flags().BoolVar(&noPlugins, "np", false, "not run plugin.\r\n禁用所有的插件")
    
    // 是否显示无头浏览器
    webScanCmd.Flags().BoolVar(&show, "show", false, "specifies whether the show the browser in headless mode.\r\n主动扫描下是否显示浏览器")
    
    // 设置需要开启的 nuclei poc
    webScanCmd.Flags().StringSliceVar(&Poc, "poc", nil, "specify the nuclei poc to run, separated by ','(example: test.yml,./test/*).\r\n自定义的nuclei 漏洞模板地址")
    webScanCmd.Flags().StringVarP(&craw, "craw", "c", "k", "Select crawler:c or k or kh. (c:Crawlergo, k:Katana Standard Mode(default), kh:(Katana Headless Mode))\r\n选择哪一个爬虫，c:Crawlergo, k:Katana 标准模式(default),kh: Katana无头模式")
    
    // 被动监听，收集流量 Security Copilot mode
    webScanCmd.Flags().StringVar(&conf.GlobalConfig.Passive.ProxyPort, "listen", "", "use proxy resource collector, value is proxy addr, (example: 127.0.0.1:9080).\r\n被动模式监听的代理地址，默认 127.0.0.1:9080")
    webScanCmd.Flags().StringVar(&conf.GlobalConfig.Passive.WebPort, "web", "9088", "Security Copilot web report port, (example: 9088)].\r\nweb页面端口，默认9088")
    webScanCmd.Flags().StringVar(&conf.GlobalConfig.Passive.WebUser, "user", "yhy", "Security Copilot web report authorized user, (example: yhy).]\r\nweb页面登录用户名，默认为yhy")
    webScanCmd.Flags().StringVar(&conf.GlobalConfig.Passive.WebPass, "pwd", "", "Security Copilot web report authorized pwd.\r\nweb页面登录密码，不指定会随机生成一个密码")
    
    // 是否阻塞，方便查看 security copilot 页面
    webScanCmd.Flags().BoolVar(&copilot, "copilot", false, "Blocking program, go to the default port 9088 to view detailed scan information.\r\n主动模式下，可以通过指定该参数阻塞程序，扫描完不退出程序，可以到 web 端口查看信息。")
    
    webScanCmd.Flags().BoolVar(&conf.NoProgressBar, "npb", false, "Turn off the progress display.\r\n关闭进度信息显示。")
    
}
