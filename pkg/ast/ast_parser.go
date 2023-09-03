package ast

import (
	"bytes"
	"encoding/json"

	"github.com/yhy0/Jie/pkg/util"
	"github.com/yhy0/logging"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"github.com/thoas/go-funk"
	"golang.org/x/net/html"
	"io"
	"os"
	"reflect"
	"regexp"
	"strings"
)

/**
  @author: yhy
  @since: 2023/3/7
  @desc: https://github1s.com/wrenchonline/glint/ast/
**/

type JsonUrl struct {
	Url     string                 `json:"url"`
	MetHod  string                 `json:"method"`
	Headers map[string]interface{} `json:"headers"`
	Data    string                 `json:"data"` //post数据
	Source  string                 `json:"source"`
	Hostid  int64                  `json:"hostid"`
}

type Attribute struct {
	Key string
	Val string
}

type NodeValue struct {
	TagName    string
	Content    string
	Attributes []*Attribute
}

type Occurence struct {
	Type     string
	Position int
	Details  Node
}

type Parser struct {
	//tokenizer *btree.BTree
	tokenizer *Node
	attr      *Attribute
	emptystr  string
}

// ByKeys is a comparison function that compares item keys and returns true
// when a is less than b.
func ByKeys(a, b interface{}) bool {
	i1, i2 := a.(*Node), b.(*Node)
	return i1.Key <= i2.Key
}

// Duplicate 去除重复元素
func Duplicate(a interface{}) (ret []interface{}) {
	va := reflect.ValueOf(a)
	for i := 0; i < va.Len(); i++ {
		if i > 0 && reflect.DeepEqual(va.Index(i-1).Interface(), va.Index(i).Interface()) {
			continue
		}
		ret = append(ret, va.Index(i).Interface())
	}
	return ret
}

// AnalyseJs Js的ast语法分析，主要目的是抓取变量，返回变量数组
func AnalyseJs(script, t string) []string {
	var params []string
	var varDiscover bool

	l := js.NewLexer(parse.NewInputString(script))
	for {
		tt, text := l.Next()
		switch tt {
		case js.ErrorToken:
			if l.Err() != io.EOF {
				logging.Logger.Debugln(t, "Error on line:", l.Err())
			}
			return params
		case js.VarToken, js.ConstToken, js.LetToken: // var, const, let
			varDiscover = true
		case js.IdentifierToken: // 获取变量名
			if varDiscover {
				params = append(params, string(text))
			}
			varDiscover = false
		default:
			if varDiscover {
				varDiscover = false
			}
		}
	}
}

// HttpParser http标签解析过滤
func (parser *Parser) HttpParser(body *string) bool {
	//color.Red(body)
	//Tree := btree.New(ByKeys)
	// parser.tokenizer = btree.New(ByKeys)
	// Tree := []Node{}
	Tree := Node{}

	z := html.NewTokenizer(strings.NewReader(*body))
	if parser.tokenizer == nil {
		parser.tokenizer = new(Node)
	}
	// lock.Lock()
	// defer lock.Unlock()
	var i = 0
	for {
		i++
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			goto processing
		case html.TextToken:
			if field, ok := Tree.Max(); ok {
				// 使用 += 进行拼接，而不是 = 赋值,
				// 防止这种 <div id="guestbook_comments">Name: ycPOCq<br />Message: rnSCKL<br /></div> 情况，这种Message: rnSCKL 会把Name: ycPOCq 覆盖
				field.Value.Content += util.BytesToString(z.Text())
			}
		case html.StartTagToken:
			//logger.Debug("html.StartTagToken:%s", string(z.Raw()))
			Attributes := make([]*Attribute, 0)
			array, _ := z.TagName()
			cx := util.BytesToString(array)
			if cx == "br" {
				continue
			}

			for {
				key, val, moreAttr := z.TagAttr()
				if moreAttr {
					mkey := util.BytesToString(key)
					mval := util.BytesToString(val)
					parser.attr = new(Attribute)
					parser.attr.Key = mkey
					parser.attr.Val = mval

					Attributes = append(Attributes, parser.attr)
				} else {
					mkey := util.BytesToString(key)
					mval := util.BytesToString(val)
					parser.attr = new(Attribute)
					parser.attr.Key = mkey
					parser.attr.Val = mval
					Attributes = append(Attributes, parser.attr)
					break
				}
			}

			Tree.Insert(i, cx, &parser.emptystr, &Attributes)
			//Tree.Set(&Node{Idx: i, Tagname: cx, Content: "", Attributes: Attributes})

		case html.EndTagToken:
			name, _ := z.TagName()
			//logger.Debug("html.EndTagToken:%s", string(z.Raw()))
			for {
				if field, ok := Tree.Max(); ok {
					if field.Value.TagName == string(name) {
						item, ok := Tree.Max()
						if ok {
							parser.tokenizer.Set(item)
							Tree.Delete(item.Key)
						} else {
							break
						}
						break
					}

					item, ok := Tree.Max()
					if ok {
						parser.tokenizer.Set(item)
						Tree.Delete(item.Key)
					} else {
						break
					}

				} else {
					break
				}
			}

		case html.SelfClosingTagToken:
			//logger.Debug("html.SelfClosingTagToken:%s", string(z.Raw()))
			Attributes := make([]*Attribute, 0)
			array, _ := z.TagName()

			cx := util.BytesToString(array)
			if cx == "br" {
				continue
			}

			for {
				key, val, moreAttr := z.TagAttr()
				if moreAttr {
					mkey := util.BytesToString(key)
					mval := util.BytesToString(val)
					parser.attr = new(Attribute)
					parser.attr.Key = mkey
					parser.attr.Val = mval
					Attributes = append(Attributes, parser.attr)
				} else {
					mkey := util.BytesToString(key)
					mval := util.BytesToString(val)
					parser.attr = new(Attribute)
					parser.attr.Key = mkey
					parser.attr.Val = mval
					Attributes = append(Attributes, parser.attr)
					break
				}
			}

			Tree.Insert(i, cx, &parser.emptystr, &Attributes)
			name, _ := z.TagName()
			for {
				if field, ok := Tree.Max(); ok {
					if field.Value.TagName == string(name) {
						// if Tree.Len() > 0 || Tree != nil {
						parser.tokenizer.Set(field)
						Tree.Delete(field.Key)
						//}
						break
					} else {
						parser.tokenizer.Set(field)
						Tree.Delete(field.Key)
						break
					}
				} else {
					break
				}
			}
			//}

		case html.CommentToken:
			Attributes := make([]*Attribute, 0)
			commentText := string(z.Text())
			parser.tokenizer.Insert(i, "comment", &commentText, &Attributes)
		}

	}
processing:

	return true
}

// GetRoot 获取根节点
func (parser *Parser) GetRoot() *Node {
	return parser.tokenizer
}

func (parser *Parser) Clear() {
	parser.tokenizer.Clear()
}

// CopyNode 只拷贝当前节点,并不拷贝其子节点
func CopyNode(tn *Node) Node {
	node := Node{Key: tn.Key, Value: tn.Value}
	return node
}

// SearchInputInResponse 搜索响应信息的位置
func SearchInputInResponse(input string, body string) []Occurence {
	parse := Parser{}
	Occurences := []Occurence{}
	Index := 0
	if len(body) == 0 {
		logging.Logger.Warning("SearchInputInResponse 获取body失败")
		return Occurences
	}
	parse.HttpParser(&body)
	tokens := parse.GetRoot()
	defer parse.Clear()

	if tokens.Length() == 0 {
		return Occurences
	}
	for _, token := range tokens.Children {
		tagname := token.Value.TagName
		// if token.Tagname == "img" {
		// 	for _, v := range *token.Attributes {
		// 		if v.Key == "onerror" {
		// 			fmt.Println("find")
		// 		}
		// 	}
		// }
		content := token.Value.Content
		attibutes := token.Value.Attributes
		if input == tagname {
			Occurences = append(Occurences, Occurence{Type: "intag", Position: Index, Details: CopyNode(token)})
		} else if funk.Contains(content, input) {
			if tagname == "comment" {
				Occurences = append(Occurences, Occurence{Type: "comment", Position: Index, Details: CopyNode(token)})
			} else if tagname == "script" {
				Occurences = append(Occurences, Occurence{Type: "script", Position: Index, Details: CopyNode(token)})
			} else if tagname == "style" {
				Occurences = append(Occurences, Occurence{Type: "html", Position: Index, Details: CopyNode(token)})
			} else {
				Occurences = append(Occurences, Occurence{Type: "html", Position: Index, Details: CopyNode(token)})
				for _, attibute := range attibutes {
					if input == attibute.Key {
						detail := Node{Value: NodeValue{TagName: tagname, Content: "key", Attributes: []*Attribute{{Key: attibute.Key, Val: attibute.Val}}}}
						// detail := Node{}}
						Occurences = append(
							Occurences,
							Occurence{
								Type:     "attibute",
								Position: Index,
								Details:  detail})
						//使用funk.Contains是因为有可能是Val是脚本
					} else if funk.Contains(attibute.Val, input) {
						detail := Node{Value: NodeValue{TagName: tagname, Content: "val", Attributes: []*Attribute{{Key: attibute.Key, Val: attibute.Val}}}}
						//detail := Node{Tagname: tagname, Content: "val", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
						Occurences = append(
							Occurences,
							Occurence{
								Type:     "attibute",
								Position: Index,
								Details:  detail})
					}
				}
			}
		} else {
			for _, attibute := range attibutes { // 判断是在name还是value上
				if input == attibute.Key {
					detail := Node{Value: NodeValue{TagName: tagname, Content: "key", Attributes: []*Attribute{{Key: attibute.Key, Val: attibute.Val}}}}
					// detail := Node{Tagname: tagname, Content: "key", Attributes: &[]Attribute{{Key: attibute.Key, Val: attibute.Val}}}
					Occurences = append(
						Occurences,
						Occurence{
							Type:     "attibute",
							Position: Index,
							Details:  detail})
				} else if funk.Contains(attibute.Val, input) {
					detail := Node{Value: NodeValue{TagName: tagname, Content: "val", Attributes: []*Attribute{{Key: attibute.Key, Val: attibute.Val}}}}
					Occurences = append(
						Occurences,
						Occurence{
							Type:     "attibute",
							Position: Index,
							Details:  detail})
				}
			}
		}
		if len(Occurences) > 0 {
			Index++
		}
	}
	return Occurences
}

// AnalyseJSFuncByFlag 分析js语法获取部分语法数据
func AnalyseJSFuncByFlag(input string, script string) (string, error) {
	o := js.Options{}
	ast, err := js.Parse(parse.NewInputString(script), o)
	if err != nil {
		return "", err
	}
	var newpayload bytes.Buffer
	logging.Logger.Debugln("Scope:", ast.Scope.String())
	logging.Logger.Debugln("JS:", ast.String())
	//ast.BlockStmt.String()
	l := js.NewLexer(parse.NewInputString(script))
	for {
		tt, text := l.Next()
		switch tt {
		case js.ErrorToken:
			if l.Err() != io.EOF {
				logging.Logger.Debugln("Error on line:", l.Err())
			}
			return newpayload.String(), nil
		case js.IdentifierToken:
			str := string(text)
			if funk.Contains(str, input) {
				logging.Logger.Debugln("flag %s exists in a Identifier ", str)
			}
		case js.StringToken:
			str := string(text)
			if funk.Contains(str, input) {
				//检测flag是否在闭合函数中
				reg := "\\(function(.*?)Stmt\\({(.*?)" + str + "(.*?)}\\)\\)"
				match, _ := regexp.MatchString(reg, ast.String())
				if match {
					logging.Logger.Debugln("var %s flag exists in a closed function", str)

					leftcloser := JsContexterLeft(input, ast.JS())
					Rightcloser := JsContexterRight(input, ast.JS())
					//判断是否是单引号还是双引号的字符串变量
					if funk.Contains(str, "'") {
						newpayload.WriteString("';" + leftcloser + " console.log(\"" + input + "\"); " + Rightcloser + "//\\")
					} else if funk.Contains(str, "\"") {
						//newpayload.WriteString("\"\";" + leftcloser + " console.log(\"" + input + "\"); " + Rightcloser + "//\\")
						newpayload.WriteString("\"\";" + leftcloser + " console.log('" + input + "'); " + Rightcloser + "//\\")
					} else {

					}

				} else {
					logging.Logger.Debugln("var %s flag exists in Statement", str)
					//判断是否是单引号还是双引号的字符串变量
					if funk.Contains(str, "'") {
						//newpayload.WriteString("'';\r console.log('" + input + "');//")
						newpayload.WriteString("'; console.log('" + input + "');//")
					} else {
						newpayload.WriteString("\"\";%0aconsole.log('" + input + "');//")
					}
				}
			}
		}
	}

}

// 反转字符串
func reverseString(s string) string {
	runes := []rune(s)
	for from, to := 0, len(runes)-1; from < to; from, to = from+1, to-1 {
		runes[from], runes[to] = runes[to], runes[from]
	}
	return string(runes)
}

func stripper(str string, substring rune, direction string) string {
	done := false
	var (
		strippedString bytes.Buffer
		s              bytes.Buffer
		retstring      bytes.Buffer
	)

	if direction == "right" {
		s.WriteString(reverseString(str))
	}
	for _, char := range s.String() {
		if char == substring && !done {
			done = true
		} else {
			strippedString.WriteString(string(char))
		}
	}
	if direction == "right" {
		retstring.WriteString(reverseString(strippedString.String()))
	}
	return retstring.String()
}

// JsContexterLeft 生成左半边的闭合xss payload
func JsContexterLeft(xsschecker string, script string) string {
	var breaker bytes.Buffer
	broken := strings.Split(script, xsschecker)
	pre := broken[0]
	re := regexp.MustCompile(`(?s)\{.*?\}|(?s)\(.*?\)|(?s)".*?"|(?s)\'.*?\'`)
	s := re.ReplaceAllString(pre, "")
	num := 0
	for idx, char := range s {
		if char == '{' {
			breaker.WriteString("}")
		} else if char == '(' {
			breaker.WriteString(";)")
		} else if char == '[' {
			breaker.WriteString("]")
		} else if char == '/' {
			if idx+1 <= len(s) {
				if s[idx+1] == '*' {
					breaker.WriteString("/*")
				}
			}
		} else if char == '}' {
			c := stripper(breaker.String(), '}', "right")
			breaker.Reset()
			breaker.WriteString(c)
		} else if char == ')' {
			c := stripper(breaker.String(), ')', "right")
			breaker.Reset()
			breaker.WriteString(c)
		} else if char == ']' {
			c := stripper(breaker.String(), ']', "right")
			breaker.Reset()
			breaker.WriteString(c)
		}
		num++
	}
	return reverseString(breaker.String())
}

// JsContexterRight 生成右半边的闭合xss payload
func JsContexterRight(xsschecker string, script string) string {
	var breaker bytes.Buffer
	var count int = 0
	var s string
	bFriststr := "function a(){"
	broken := strings.Split(script, xsschecker)
	pre := broken[1]
	pre0 := broken[0] //检测else 对于flag左半边边是否是子集    比如 if else 外部有个 if 包含了
	//fmt.Println(pre0)
	/*
		pre0 == function loadTest () { var time = 11; if (1) { if (time < 20) { if (1) { var x = '
	*/
	Lpayload := strings.Count(pre0, "{")

	//pre = "'); }; } else { var x = '2222222'; }; };"
	//re := regexp.MustCompile(`(?s)\{.*?\}|(?s)\(.*?\)|(?s)".*?"|(?s)\'.*?\'`)
	//// '; }; } else { var x = '2222222'; }; };    //过滤前
	//// 2222222'; }; }; 					//过滤后
	///这里可以过滤到else有什么问题可以在这里调试
	elses := strings.Split(pre, "else")
	//这里存在else的因素所以必须想办法使生成的payload让这个函数闭合，我采取的思路就是else右半边的 '}' 与 左半边的 '}' 相减，多出来的数目在payload后面添加 }
	if len(elses) >= 2 {
		//计算else左边反括号数量
		LbracketsCount := strings.Count(elses[0], "}")
		//计算else右边反括号数量
		RbracketsCount := strings.Count(elses[1], "}")
		//计算闭合
		cot := Lpayload - RbracketsCount
		count = RbracketsCount - LbracketsCount + 1 - 1 - cot // + 1 是因为else的存在，-1是因为我函数开头以 function%20a(){ 的存在 ,cot判断else是否有外部闭合的情况
		s = pre
	} else {
		s = strings.Replace(pre, "}", "", 1) //1是因为我函数开头以 function%20a(){ 的存在
	}
	num := 0
	for idx, char := range s {
		if char == '}' {
			breaker.WriteString(" {)1(fi")
		} else if char == ')' {
			breaker.WriteString("(") //这个估计改下1(
		} else if char == ']' {
			breaker.WriteString("[")
		} else if char == '*' {
			if idx+1 <= len(s) {
				if s[idx+1] == '/' {
					breaker.WriteString("*/")
				}
			}
		} else if char == '{' {
			c := stripper(breaker.String(), '{', "left")
			breaker.Reset()
			breaker.WriteString(c)
		} else if char == '(' {
			c := stripper(breaker.String(), '(', "left")
			breaker.Reset()
			breaker.WriteString(c)
		} else if char == '[' {
			c := stripper(breaker.String(), '[', "left")
			breaker.Reset()
			breaker.WriteString(c)
		}
		num++
	}
	var exportbyelse bytes.Buffer
	for z := 0; z < count; z++ {
		exportbyelse.WriteString("}")
	}
	return bFriststr + reverseString(breaker.String()) + exportbyelse.String()
}

func SaveCrawOutPut(ResultList map[string][]JsonUrl, FilePath string) {
	// var data []byte
	if len(ResultList) > 0 {
		data, err := json.Marshal(ResultList)
		if err != nil {
			logging.Logger.Errorf("%s", err.Error())
			return
		}
		fp, err := os.OpenFile(FilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
		if err != nil {
			logging.Logger.Errorf("%s", err.Error())
			return
		}
		defer fp.Close()
		_, err = fp.Write(data)
		if err != nil {
			logging.Logger.Errorf("%s", err.Error())
			return
		}
	}

}
