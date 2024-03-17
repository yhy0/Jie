package crawler

import (
    "github.com/projectdiscovery/katana/pkg/output"
    "github.com/yhy0/logging"
    "testing"
)

/**
  @author: yhy
  @since: 2023/1/31
  @desc: //TODO
**/

func TestKatana(t *testing.T) {
    logging.Logger = logging.New(false, "", "1", true)
    
    out := func(result output.Result) { // Callback function to execute for result
        // if ValidatePath(result.Request.URL) {
        //     logging.Logger.Infoln(result.Request.URL)
        // }
        logging.Logger.Infoln(result.Request.URL)
    }
    
    Katana("https://www.baidu.com", true, true, out)
}
