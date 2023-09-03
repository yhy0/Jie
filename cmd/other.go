package cmd

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/scan/brute"
	"github.com/yhy0/Jie/scan/traversal"
	"github.com/yhy0/logging"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var otherCmd = &cobra.Command{
	Use:   "other",
	Short: "other scan && exp",
	Run: func(cmd *cobra.Command, args []string) {
		logging.New(conf.GlobalConfig.Options.Debug, "", "Jie", false)
		// 初始化 session ,todo 后续优化一下，不同网站共用一个不知道会不会出问题，应该不会
		httpx.NewSession()
		switch conf.GlobalConfig.Options.Mode {
		case "bb":
			user, pwd, _ := brute.BasicBrute(conf.GlobalConfig.Options.Target)
			if user != "" {
				fmt.Println(aurora.Red(fmt.Sprintf("[Success] %v %v", user, pwd)))
			}
		case "nat":
			traversal.NginxAlias(conf.GlobalConfig.Options.Target, "", nil)
		}
	},
}

func otherCmdInit() {
	rootCmd.AddCommand(otherCmd)
	otherCmd.Flags().StringVarP(&conf.GlobalConfig.Options.Mode, "mode", "m", "", "mode (eg: bb:basic brute、nat:Nginx Alias Traversal)")
	otherCmd.MarkFlagRequired("mode")
}
