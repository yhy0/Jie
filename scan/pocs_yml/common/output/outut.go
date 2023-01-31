package output

import (
	"github.com/remeh/sizedwaitgroup"
	"github.com/yhy0/Jie/pkg/input"
	JieOutput "github.com/yhy0/Jie/pkg/output"
	"github.com/yhy0/Jie/scan/pocs_yml/common/check"
	"github.com/yhy0/Jie/scan/pocs_yml/common/structs"
	"time"
)

func InitOutput(in *input.Input) (chan structs.Result, *sizedwaitgroup.SizedWaitGroup) {
	outputChannel := make(chan structs.Result)
	outputs := make([]structs.Output, 0)
	outputWg := sizedwaitgroup.New(1)
	outputWg.Add()

	// inject StrandardOutput
	outputs = append(outputs, &structs.StandardOutput{})

	go func() {
		defer outputWg.Done()

		for result := range outputChannel {
			//for _, output := range outputs {
			//
			//	//output.Write(result)
			//}

			// 这里返回扫描结果
			if result.SUCCESS() {
				JieOutput.OutChannel <- JieOutput.VulMessage{
					DataType: "web_vul",
					Plugin:   "POC",
					VulData: JieOutput.VulData{
						CreateTime: time.Now().Format("2006-01-02 15:04:05"),
						Target:     in.Target,
						Method:     in.Method,
						Ip:         in.Ip,
						Param:      in.Kv,
						Request:    result.Get().Req,
						Response:   result.Get().Res,
						Payload:    result.Get().PocName,
					},
					Level: JieOutput.Critical,
				}
			}
			pocResult, ok := result.(*structs.PocResult)
			if ok {
				check.PutPocResult(pocResult)
			}
		}
	}()

	return outputChannel, &outputWg
}
