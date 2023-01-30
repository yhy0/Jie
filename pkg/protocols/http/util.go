package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/thoas/go-funk"
	"github.com/yhy0/Jie/logging"
	"io"
	"io/ioutil"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
)

/*
*

	@author: yhy
	@since: 2023/1/30
	@desc: //TODO

*
*/
const (
	applicationJson       = "application/json"
	applicationUrlencoded = "application/x-www-form-urlencoded"
	multipartData         = "multipart/form-data"
	unknown               = "unknown"
)

const MAX_SEND_COUNT = 10

// Param describes an individual posted parameter.
type Param struct {
	// Name of the posted parameter.
	Name string `json:"name"`
	// Value of the posted parameter.
	Value string `json:"value,omitempty"`
	// Filename of a posted file.
	Filename string `json:"fileName,omitempty"`
	// ContentType is the content type of posted file.
	ContentType string `json:"contentType,omitempty"`

	FileHeader   textproto.MIMEHeader
	FileSize     int64
	FileContent  []byte
	IsFile       bool
	Boundary     string
	FilenotFound bool
	IsBase64     bool
	Index        int //
}

type Variations struct {
	// MimeType is the MIME type of the posted data.
	MimeType string `json:"mimeType"`
	// Params is a list of posted parameters (in case of URL encoded parameters).
	Params []Param `json:"params"`
	// Text contains the posted data. Although its type is string, it may contain
	// binary data.
	Text string `json:"text"`
}

func (p Variations) Len() int {
	return len(p.Params)
}

// Less 顺序有低到高排序
func (p Variations) Less(i, j int) bool {
	return p.Params[i].Index < p.Params[j].Index
}

func (p Variations) Swap(i, j int) {
	p.Params[i], p.Params[j] = p.Params[j], p.Params[i]
}

// ParseUri 对请求进行格式化
func ParseUri(uri string, body []byte, method string, contentType string, headers map[string]string) (*Variations, error) {
	var (
		err        error
		index      int
		variations Variations
	)

	jsonMap := make(map[string]interface{})
	if strings.ToUpper(method) == "POST" {
		if len(body) > 0 {
			switch getContentType(strings.ToLower(contentType)) {
			case applicationJson:
				err := json.Unmarshal(body, &jsonMap)
				if err != nil {
					return nil, err
				}
				for k, v := range jsonMap {
					index++
					if v != nil {
						if value, ok := v.(string); ok {
							Post := Param{Name: k, Value: value, Index: index, ContentType: contentType}
							variations.Params = append(variations.Params, Post)
						}
					}

				}
				variations.MimeType = contentType
			case applicationUrlencoded:
				strs := strings.Split(string(body), "&")
				for i, kv := range strs {
					kvs := strings.Split(string(kv), "=")
					if len(kvs) == 2 {
						key := kvs[0]
						value := kvs[1]
						Post := Param{Name: key, Value: value, Index: i, ContentType: contentType}
						variations.Params = append(variations.Params, Post)
					} else {
						logging.Logger.Error("exec function strings.Split fail")
						return nil, err
					}
				}
				variations.MimeType = contentType
			case multipartData:
				var iindex = 0
				var boundary string
				//base64.StdEncoding.DecodeString (
				// array := string()
				iobody := bytes.NewReader(body)
				req, err := http.NewRequest(method, uri, iobody)

				for k, v := range headers {
					req.Header[k] = []string{v}
				}

				if err != nil {
					logging.Logger.Error(err.Error())
					return nil, err
				}

				reader, err := req.MultipartReader()
				if err != nil {
					logging.Logger.Error(err.Error())
					return nil, err
				}

				_, params, err := mime.ParseMediaType(contentType)
				if err != nil {
					logging.Logger.Error("mime.ParseMediaType :", err)
				}
				if value, ok := params["boundary"]; ok {
					boundary = value
				}

				for {
					var isfile = false
					if reader == nil {
						break
					}
					p, err := reader.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						logging.Logger.Error("mime.ParseMediaType :", err)
						return nil, err
					}

					body, err := ioutil.ReadAll(p)
					if err != nil {
						p.Close()
						return nil, err
					}
					iindex++
					if p.FileName() != "" {
						isfile = true
					}

					variations.MimeType = contentType
					variations.Params = append(variations.Params, Param{
						Name:        p.FormName(),
						Boundary:    boundary,
						Filename:    p.FileName(),
						ContentType: p.Header.Get("Content-Type"),
						// FileContent: body,
						Value:  string(body),
						IsFile: isfile,
						Index:  iindex,
					})

					p.Close()
				}
			}

			sort.Sort(variations)
			return &variations, nil
		} else {
			return nil, fmt.Errorf("post data is empty")
		}

	} else if strings.ToUpper(method) == "GET" {
		if !funk.Contains(uri, "?") {
			return nil, fmt.Errorf("GET data is empty")
		}
		urlparams := strings.Split(uri, "?")[1]
		strs := strings.Split(urlparams, "&")
		//params := Param{}
		for i, kv := range strs {
			kvs := strings.Split(kv, "=")
			if len(kvs) == 2 {
				key := kvs[0]
				value := kvs[1]
				variations.Params = append(variations.Params, Param{Name: key, Value: value, Index: i, ContentType: contentType})
			} else {
				err = fmt.Errorf("exec function strings.Split fail")
				logging.Logger.Error("%s", err.Error())
				return nil, err
			}
		}
		sort.Sort(variations)
		return &variations, nil
	} else {
		err = fmt.Errorf("method not supported")
	}
	return nil, err
}

func getContentType(data string) string {
	if funk.Contains(data, applicationJson) {
		return applicationJson
	}
	if funk.Contains(data, applicationUrlencoded) {
		return applicationUrlencoded
	}
	if funk.Contains(data, multipartData) {
		return multipartData
	}
	return unknown
}

func (p *Variations) Release() string {

	var buf bytes.Buffer
	mjson := make(map[string]interface{})
	if p.MimeType == "application/json" {
		for _, Param := range p.Params {
			mjson[Param.Name] = Param.Value
		}
		jsonary, err := json.Marshal(mjson)
		if err != nil {
			logging.Logger.Error(err.Error())
		}
		buf.Write(jsonary)
	} else if funk.Contains(p.MimeType, "multipart/form-data") {
		// bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(&buf)
		// bodyWriter.CreateFormFile(p.Params[0], p.Params[0].Filename)

		if p.Params[0].Boundary != "" {
			bodyWriter.SetBoundary(p.Params[0].Boundary)
		}

		for _, Param := range p.Params {
			if Param.IsFile {

				h := make(textproto.MIMEHeader)
				h.Set("Content-Disposition",
					fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
						escapeQuotes(Param.Name), escapeQuotes(Param.Filename)))
				h.Set("Content-Type", Param.ContentType)
				part, err := bodyWriter.CreatePart(h)
				if err != nil {
					logging.Logger.Error(err.Error())
				}
				// 写入文件数据到multipart，和读取本地文件方法的唯一区别
				_, err = part.Write([]byte(Param.Value))
			} else {
				_ = bodyWriter.WriteField(Param.Name, Param.Value)
			}
		}
		bodyWriter.Close()
		// fmt.Println(buf.String())
	} else {
		for i, Param := range p.Params {
			buf.WriteString(Param.Name + "=" + Param.Value)
			if i != p.Len()-1 {
				buf.WriteString("&")
			}
		}
	}

	return buf.String()
}

func (p Variations) Set(key string, value string) error {
	for i, Param := range p.Params {
		if Param.Name == key {
			p.Params[i].Value = value
			return nil
		}
	}
	return fmt.Errorf("not found: %s", key)
}

func (p *Variations) SetPayload(uri string, payload string, method string, key ...[]string) []string {
	var result []string
	if strings.ToUpper(method) == "POST" {
		for idx, kv := range p.Params {
			if len(key) > 0 { // 限定替换关键参数名
				if !funk.Contains(key, kv.Name) {
					continue
				}
			}
			//小于MAX_SEND_COUNT一个链接参数不能超过MAX_SEND_COUNT
			if idx <= MAX_SEND_COUNT {
				p.Set(kv.Name, payload)
				result = append(result, p.Release())
				p.Set(kv.Name, kv.Value)
			} else {
				logging.Logger.Warning("当前url超出参数最大发送参数,自动pass不填写参数")
			}

		}
	} else if strings.ToUpper(method) == "GET" {
		u, err := url.Parse(uri)
		if err != nil {
			logging.Logger.Debug(err.Error())
			return nil
		}
		v := u.Query()
		for idx, kv := range p.Params {
			if len(key) > 0 { // 限定替换关键参数名
				if !funk.Contains(key, kv.Name) {
					continue
				}
			}
			if idx <= MAX_SEND_COUNT {
				v.Set(kv.Name, payload)
				result = append(result, strings.Split(uri, "?")[0]+"?"+v.Encode())
				v.Set(kv.Name, kv.Value)
			} else {
				logging.Logger.Warning("当前url超出参数最小发送数,自动pass不填写参数")
			}
		}
	}
	return result
}

func (p *Variations) SetPayloadByindex(index int, uri string, payload string, method string) string {
	var result string
	if strings.ToUpper(method) == "POST" {
		for idx, kv := range p.Params {
			//小于5一个链接参数不能超过5
			if idx <= MAX_SEND_COUNT {
				if idx == index {
					p.Set(kv.Name, payload)
					str := p.Release()
					p.Set(kv.Name, kv.Value)
					return str
				}
			} else {
				logging.Logger.Warning("当前url超出参数最小发送数,自动pass不填写参数")
			}

		}
	} else if strings.ToUpper(method) == "GET" {
		u, err := url.Parse(uri)
		if err != nil {
			logging.Logger.Error(err.Error())
			return ""
		}
		v := u.Query()
		for idx, kv := range p.Params {
			if idx <= MAX_SEND_COUNT {
				if idx == index {
					p.Set(kv.Name, payload)
					stv := p.Release()
					str := strings.Split(uri, "?")[0] + "?" + stv
					v.Set(kv.Name, kv.Value)
					return str
				}
			} else {
				logging.Logger.Warning("当前url超出参数最小发送数,自动pass不填写参数")
			}
		}
	}
	return result
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

func Header(headers http.Header) string {
	var header string
	for key, value := range headers {
		header += fmt.Sprintf("%s: %s", key, strings.Join(value, "; "))
	}
	return header
}
