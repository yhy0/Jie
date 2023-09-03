package cmd

import (
	"github.com/spf13/cobra"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/scan/pocs_go/log4j"
	"github.com/yhy0/logging"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var log4jCmd = &cobra.Command{
	Use:   "log4j",
	Short: "log4j scan && exp",
	Run: func(cmd *cobra.Command, args []string) {
		logging.New(conf.GlobalConfig.Options.Debug, "", "Jie", false)
		// 初始化 session ,todo 后续优化一下，不同网站共用一个不知道会不会出问题，应该不会
		httpx.NewSession()
		log4j.Scan(conf.GlobalConfig.Options.Target, "GET", "")
	},
}

func log4jCmdInit() {
	rootCmd.AddCommand(log4jCmd)
	log4jCmd.Flags().StringVarP(&conf.GlobalConfig.Reverse.Host, "host", "h", "https://dig.pm", "dns host")
	log4jCmd.Flags().StringVarP(&domain, "domain", "d", "", "domain ")
}
