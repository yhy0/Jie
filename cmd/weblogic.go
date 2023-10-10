package cmd

import (
	"github.com/spf13/cobra"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/scan/java/weblogic"
)

/**
   @author yhy
   @since 2023/8/20
   @desc //TODO
**/

var (
	name int
	mode string
	cmd  string
)

var webLogicCmd = &cobra.Command{
	Use:   "weblogic",
	Short: "WebLogic scan && exp",
	Run: func(cmd *cobra.Command, args []string) {
		for _, target := range conf.GlobalConfig.Options.Targets {
			if mode == "scan" {
				switch name {
				case 1:
					weblogic.CVE_2014_4210(target)
				case 2:
					weblogic.CVE_2017_3506(target)
				case 3:
					weblogic.CVE_2017_10271(target)
				case 4:
					weblogic.CVE_2018_2894(target)
				case 5:
					weblogic.CVE_2019_2725(target)
				case 6:
					weblogic.CVE_2019_2729(target)
				case 7:
					weblogic.CVE_2020_2883(target)
				case 8:
					weblogic.CVE_2020_14882(target)
				case 9:
					weblogic.CVE_2020_14883(target)
				case 10:
					weblogic.CVE_2021_2109(target)
				case 0:
					weblogic.CVE_2014_4210(target)
					weblogic.CVE_2017_3506(target)
					weblogic.CVE_2017_10271(target)
					weblogic.CVE_2018_2894(target)
					weblogic.CVE_2019_2725(target)
					weblogic.CVE_2019_2729(target)
					weblogic.CVE_2020_2883(target)
					weblogic.CVE_2020_14882(target)
					weblogic.CVE_2020_14883(target)
					weblogic.CVE_2021_2109(target)
				}
			}
		}

	},
}

func webLogicCmdInit() {
	rootCmd.AddCommand(webLogicCmd)
	webLogicCmd.Flags().IntVarP(&name, "name", "n", 0, "vul name: 1:CVE_2014_4210, 2:CVE_2017_3506, 3:CVE_2017_10271, 4:CVE_2018_2894, 5:CVE_2019_2725, 6:CVE_2019_2729, 7:CVE_2020_2883, 8:CVE_2020_14882, 9:CVE_2020_14883, 10:CVE_2021_2109, 0:all")
	webLogicCmd.Flags().StringVarP(&mode, "mode", "m", "scan", "Specify work mode: scan exp")
	webLogicCmd.Flags().StringVarP(&cmd, "cmd", "c", "id", "Exec command(Only works on mode exp.)")
}
