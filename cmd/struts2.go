package cmd

import (
	"github.com/spf13/cobra"
	"github.com/yhy0/Jie/conf"
	"github.com/yhy0/Jie/scan/java/struts2"
)

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

var struts2Cmd = &cobra.Command{
	Use:   "s2",
	Short: "Struts2 scan && exp",
	Run: func(cmd *cobra.Command, args []string) {
		struts2.S2(conf.GlobalConfig.Options)
	},
}

func struts2CmdInit() {
	rootCmd.AddCommand(struts2Cmd)
	struts2Cmd.Flags().StringVarP(&conf.GlobalConfig.Options.S2.Name, "name", "n", "", "vul name: S2-001, S2-003, S2-005, S2-007, S2-008, S2-009, S2-012, S2-013, S2-015, S2-016, S2-019,\n\t\tS2-029, S2-032, S2-033, S2-037, S2-045, S2-046, S2-048, S2-052, S2-053, S2-devMode, S2-057,allPoc(除了s2-052)")
	struts2Cmd.Flags().StringVarP(&conf.GlobalConfig.Options.S2.Mode, "mode", "m", "scan", "Specify work mode: scan exec")
	struts2Cmd.Flags().StringVarP(&conf.GlobalConfig.Options.S2.CMD, "cmd", "c", "id", "Exec command(Only works on mode exec.)")
	struts2Cmd.Flags().StringVarP(&conf.GlobalConfig.Options.S2.Body, "body", "b", "name=fuckit&pass=qwer", "Specific vulnerability packets")
}
