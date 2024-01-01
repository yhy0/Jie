package cmd

import (
    "github.com/spf13/cobra"

    "github.com/yhy0/Jie/conf"
    "github.com/yhy0/Jie/scan/Pocs/apollo"
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
