package cmd

import (
	"bufio"
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/logging"
	"io"
	"os"
	"strings"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var (
	Plugins []string
	Poc     []string
	Listen  string
	host    string
	domain  string
	show    bool
)

var rootCmd = &cobra.Command{
	Use:   "Jie",
	Short: "A Powerful security assessment and utilization tools",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		initTargetList()

		logging.New(conf.GlobalConfig.Options.Debug, "", "Jie", true)
		// 初始化 session
		httpx.NewSession()
		if conf.GlobalConfig.Options.Output != "" {
			go output.GenerateVulnReport(conf.GlobalConfig.Options.Output)
		}

		go func() {
			for v := range output.OutChannel {
				if conf.GlobalConfig.Options.Output != "" {
					output.VulMessageChan <- v
				}
				logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
			}
		}()

	},
}

func init() {
	fmt.Println("\t" + aurora.Green(conf.Banner).String())
	fmt.Println("\t\t" + aurora.Red("v"+conf.Version).String())
	fmt.Println("\t" + aurora.Blue(conf.Website).String() + "\n")

	fmt.Println(aurora.Red("Use with caution. You are responsible for your actions.").String())
	fmt.Println(aurora.Red("Developers assume no liability and are not responsible for any misuse or damage.").String() + "\n")

	conf.GlobalConfig = &conf.Config{}

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().StringVarP(&conf.GlobalConfig.Options.Target, "target", "t", "", "target")
	rootCmd.PersistentFlags().StringVarP(&conf.GlobalConfig.Options.TargetFile, "file", "f", "", "target file")
	rootCmd.PersistentFlags().StringVarP(&conf.GlobalConfig.Options.Output, "out", "o", "", "output report file(eg:vulnerability_report.html)")
	rootCmd.PersistentFlags().StringVar(&conf.GlobalConfig.Options.Proxy, "proxy", "", "proxy, (example: --proxy http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().BoolVar(&conf.GlobalConfig.Options.Debug, "debug", false, "debug")
	rootCmd.MarkPersistentFlagRequired("target")

	webScanCmdInit()
	shiroCmdinit()
	struts2CmdInit()
	webLogicCmdInit()
	log4jCmdInit()
	apolloCmdInit()
	fastjsonCmdInit()
	otherCmdInit()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initTargetList() {
	if conf.GlobalConfig.Options.Target != "" {
		conf.GlobalConfig.Options.Targets = append(conf.GlobalConfig.Options.Targets, conf.GlobalConfig.Options.Target)
	}
	if conf.GlobalConfig.Options.TargetFile != "" {
		file, err := os.Open(conf.GlobalConfig.Options.TargetFile)
		if err != nil {
			fmt.Println("文件不存在", err)
			return
		}
		buffer := bufio.NewReader(file)

		for {
			line, err := buffer.ReadString('\n')
			line = strings.TrimSpace(line)
			if err != nil {
				if err == io.EOF {
					return
				}
				fmt.Println("未知错误", err)
				return
			}
			conf.GlobalConfig.Options.Targets = append(conf.GlobalConfig.Options.Targets, line)
		}
	}

	return
}
