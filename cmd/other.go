package cmd

import (
	"fmt"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/scan/brute"
	"github.com/yhy0/Jie/scan/fuzz/bbscan"
	"github.com/yhy0/Jie/scan/fuzz/traversal"
	"github.com/yhy0/Jie/scan/swagger"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var otherCmd = &cobra.Command{
	Use:   "other",
	Short: "other scan && exp bb:BasicBrute、swagger:Swagger、nat:NginxAliasTraversal、bbscan:bbscan)",
	Run: func(cmd *cobra.Command, args []string) {
		for _, target := range conf.GlobalConfig.Options.Targets {
			switch conf.GlobalConfig.Options.Mode {
			case "bb":
				user, pwd, _ := brute.BasicBrute(target)
				if user != "" {
					fmt.Println(aurora.Red(fmt.Sprintf("[Success] %v %v", user, pwd)))
				}
			case "nat":
				traversal.NginxAlias(target, "", nil)
			case "swagger":
				swagger.Scan(target, "")
			case "bbscan":
				bbscan.BBscan(target, "", nil, nil)
			}
		}
	},
}

func otherCmdInit() {
	rootCmd.AddCommand(otherCmd)
	otherCmd.Flags().StringVarP(&conf.GlobalConfig.Options.Mode, "mode", "m", "", "mode (eg: bb:basic brute、nat:Nginx Alias Traversal)")
	otherCmd.MarkFlagRequired("mode")
}
