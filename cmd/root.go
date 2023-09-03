package cmd

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/logging"
	"os"
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
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here
	},
}

func init() {
	fmt.Println("\t" + aurora.Green(conf.Banner).String())
	fmt.Println("\t\t" + aurora.Red("v"+conf.Version).String())
	fmt.Println("\t" + aurora.Blue(conf.Website).String() + "\n")

	fmt.Println(aurora.Red("Use with caution. You are responsible for your actions.").String())
	fmt.Println(aurora.Red("Developers assume no liability and are not responsible for any misuse or damage.").String() + "\n")

	go func() {
		for v := range output.OutChannel {
			logging.Logger.Infoln(aurora.Red(v.PrintScreen()).String())
		}
	}()
	conf.GlobalConfig = &conf.Config{}

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.PersistentFlags().StringVarP(&conf.GlobalConfig.Options.Target, "target", "t", "", "target")
	rootCmd.PersistentFlags().StringVar(&conf.GlobalConfig.Options.Proxy, "proxy", "", "proxy, (example: --proxy http://127.0.0.1:8080)")
	rootCmd.PersistentFlags().BoolVar(&conf.GlobalConfig.Options.Debug, "debug", false, "debug")
	rootCmd.MarkPersistentFlagRequired("target")
	webScanCmdInit()
	shiroCmdinit()
	struts2CmdInit()
	webLogicCmdInit()
	log4jCmdInit()
	apolloCmdInit()
	otherCmdInit()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
