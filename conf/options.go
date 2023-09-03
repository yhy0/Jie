package conf

/**
   @author yhy
   @since 2023/8/19
   @desc //TODO
**/

type Options struct {
	// target URLs/hosts to scan
	Target string
	Debug  bool
	// http/socks5 proxy to use
	Proxy string
	// Timeout is the seconds to wait for a response from the server.
	TimeOut int
	S2      S2
	Shiro   Shiro
	Mode    string
}

type S2 struct {
	Mode        string
	Name        string
	Body        string
	CMD         string
	ContentType string
}

type Shiro struct {
	Mode     string
	Cookie   string
	Platform string
	Key      string
	KeyMode  string
	Gadget   string
	CMD      string
	Echo     string
}
