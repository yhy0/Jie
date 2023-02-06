package sqlInjection

//
//import (
//	"github.com/yhy0/Jie/logging"
//	"github.com/yhy0/Jie/pkg/input"
//	"math"
//	"time"
//)
//
///**
//  @author: yhy
//  @since: 2023/2/6
//  @desc: //TODO
//**/
//
//var (
//	WAFCheck          = true
//	SimilarityRatio   = 0.999
//	LowerRatioBound = 0.02
//	UpperRatioBound = 0.98
//	DiffTolerance   = 0.05
//
//	CloseType = map[int]string{0: `'`, 1: `"`, 2: ``, 3: `')`, 4: `")`}
//
//	FormatExceptionStrings = []string{
//		"Type mismatch", "Error converting", "Please enter a", "Conversion failed", "String or binary data would be truncated", "Failed to convert", "unable to interpret text value", "Input string was not in a correct format", "System.FormatException", "java.lang.NumberFormatException", "ValueError: invalid literal", "TypeMismatchException", "CF_SQL_INTEGER", "CF_SQL_NUMERIC", " for CFSQLTYPE ", "cfqueryparam cfsqltype", "InvalidParamTypeException", "Invalid parameter type", "Attribute validation error for tag", "is not of type numeric", "<cfif Not IsNumeric(", "invalid input syntax for integer", "invalid input syntax for type", "invalid number", "character to number conversion error", "unable to interpret text value", "String was not recognized as a valid", "Convert.ToInt", "cannot be converted to a ", "InvalidDataException", "Arguments are of the wrong type",
//	}
//
//	// HeuristicCheckAlphabet 用于启发式检查的字母表
//	HeuristicCheckAlphabet = []string{`"`, `'`, `)`, `(`, `,`, `.`}
//
//	DbmsErrors = map[string][]string{
//		"MySQL": {`SQL syntax.*MySQL`, `Warning.*mysql_.*`, `valid MySQL result`, `MySqlClient\.`},
//		"PostgreSQL": {`PostgreSQL.*ERROR`, `Warning.*\Wpg_.*`, `valid PostgreSQL result`, `Npgsql\.`},
//		"Microsoft SQL Server": {`Driver.* SQL[\-\_\ ]*Server`, `OLE DB.* SQL Server`, `(\W|\A)SQL Server.*Driver`, `Warning.*mssql_.*`, `(\W|\A)SQL Server.*[0-9a-fA-F]{8}`, `(?s)Exception.*\WSystem\.Data\.SqlClient\.`, `(?s)Exception.*\WRoadhouse\.Cms\.`},
//		"Microsoft Access": {`Microsoft Access Driver`, `JET Database Engine`, `Access Database Engine`},
//		"Oracle": {`\bORA-[0-9][0-9][0-9][0-9]`, `Oracle error`, `Oracle.*Driver`, `Warning.*\Woci_.*`, `Warning.*\Wora_.*`},
//		"IBM DB2": {`CLI Driver.*DB2`, `DB2 SQL error`, `\bdb2_\w+\(`},
//		"SQLite": {`SQLite/JDBCDriver`, `SQLite.Exception`, `System.Data.SQLite.SQLiteException`, `Warning.*sqlite_.*`, `Warning.*SQLite3::`, `\[SQLITE_ERROR\]`},
//		"Sybase": {`(?i)Warning.*sybase.*`, `Sybase message`, `Sybase.*Server message.*`}
//	}
//)
//
//
//
//func sqlmap(c *input.CrawlResult) {
//	//做一些前置检查 避免无意义的后续检测
//	if c.StatusCode == 404 {
//		logging.Logger.Warnln(c.Target, " 原始请求资源不存在, ", c.StatusCode)
//		return
//	}
//
//	if len(c.Param) == 0 {
//		logging.Logger.Warnln(c.Target, " 无可供注入参数")
//		return
//	}
//
//	//waf 只判断作为提示信息 不做进一步操作 如果检出存在注入 则可以考虑附加信息
//
//	//开始启发式sql注入检测
//
//	 // TEMPLATE_PAGE_RSP后续计算pageratio做对比的正常请求页面
//
//	heuristicCheckIfInjectable(c.Url, req, c.IndexBody)
//
//
//}
