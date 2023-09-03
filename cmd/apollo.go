package cmd

import (
	"github.com/spf13/cobra"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/pkg/protocols/httpx"
	"github.com/yhy0/Jie/scan/apollo"
	"github.com/yhy0/logging"
)

/**
   @author yhy
   @since 2023/8/20
   @desc //TODO
**/

var (
	as string
	cs string
)

var apolloCmd = &cobra.Command{
	Use:   "apollo",
	Short: "apollo scan && exp",
	Run: func(cmd *cobra.Command, args []string) {
		logging.New(conf.GlobalConfig.Options.Debug, "", "Jie", false)
		// 初始化 session ,todo 后续优化一下，不同网站共用一个不知道会不会出问题，应该不会
		httpx.NewSession()

		as = conf.GlobalConfig.Options.Target
		apollo.Run(as, cs)
	},
}

func apolloCmdInit() {
	rootCmd.AddCommand(apolloCmd)
	apolloCmd.Flags().StringVarP(&as, "as", "a", "", "adminService url(-t)")
	apolloCmd.Flags().StringVarP(&cs, "cs", "c", "", "configService, spring Eureka url")
	apolloCmd.MarkFlagRequired("cs")
}
