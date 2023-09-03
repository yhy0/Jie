/*!
 * thx:
 * https://github.com/AsaiKen/dom-based-xss-finder
 * License: MIT
 */

function __xssfinder_push_dmo_vul(sources, sinkLabel) {
    let results = [];
    sources.forEach(
        (source) => {
            let r = {
                url: location.href,
                source,
                sink: __xssfinder_set_track_chian(sinkLabel)
            }
            results.push(r);
        }
    )
    // chrome Runtime.addBinding ==> xssfinderPushDomVul
    window.xssfinderPushDomVul(JSON.stringify(results));
}

const __xssfinder_String = function (str, parent) {
    this.str = '' + str;
    this.sources = []; // 传播记录
    parent.sources.forEach(e => this.sources.push(e));

    this.valueOf = function () {
        return this;
    };

    this.toString = function () {
        return this.str;
    };

    // str.length
    Object.defineProperty(this, 'length', {
        set: () => null,
        get: () => this.str.length
    });

    // str[i]
    for (let i = 0; i < this.str.length; i++) {
        Object.defineProperty(this, i, {
            set: () => null,
            get: () => new __xssfinder_String(this.str[i], this)
        });
    }
    // patch __xssfinder_String_flag 标识
    Object.defineProperty(this, '__xssfinder_String_flag', {
        set: () => null,
        get: () => true
    });
};
__xssfinder_String.prototype = String.prototype;

function __is_xssfinder_string(o) {
    return o && o.__xssfinder_String_flag;
}

function __is_xssfinder_string_html(o) {
    // <svg/onload=alert()>
    o = __convert_to_xssfinder_string_if_location(o);
    return __is_xssfinder_string(o);
}

function __is_xssfinder_string_data_html(o) {
    // data:text/html,<script>alert(1)</script>
    o = __convert_to_xssfinder_string_if_location(o);
    return __is_xssfinder_string(o);
}

function __is_xssfinder_string_script(o) {
    // alert()
    // javascript:alert()
    o = __convert_to_xssfinder_string_if_location(o);
    return __is_xssfinder_string(o);
}

function __is_xssfinder_string_url(o) {
    // //14.rs
    o = __convert_to_xssfinder_string_if_location(o);
    return __is_xssfinder_string(o);
}

function __convert_to_xssfinder_string_if_location(o) {
    if (o === window.location) {
        o = new __xssfinder_String(o.toString(), {
            sources: [__xssfinder_set_track_chian('window.location')],
        });
    }
    return o;
}

function __xssfinder_set_track_chian(label) {
    return { label, stacktrace: __xssfinder_get_stacktrace() };
}

/*
获取当前堆栈信息
Error
    at <anonymous>:1:1
    at http://example.com/index.html:12:156
*/
function __xssfinder_get_stacktrace() {
    const o = {};
    Error.captureStackTrace(o);

    const regExp = /(https?:\/\/\S+):(\d+):(\d+)/;

    return o.stack.replace(/^Error\n/, '')
        .replace(/^\s+at\s+/mg, '')
        .split('\n')
        .filter(e => regExp.test(e))
        .map(e => {
            const m = e.match(regExp);
            const url = m[1];
            const line = m[2]; // start from 1
            const column = m[3]; // start from 1
            return { url, line, column };
        });
}


(function () {
    ///////////////////////////////////////////////
    // String.prototype track chians
    ///////////////////////////////////////////////
    const _oldanchor = String.prototype.anchor;
    String.prototype.anchor = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldanchor.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldanchor.apply(this, arguments);
    };

    const _oldbig = String.prototype.big;
    String.prototype.big = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldbig.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldbig.apply(this, arguments);
    };

    const _oldblink = String.prototype.blink;
    String.prototype.blink = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldblink.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldblink.apply(this, arguments);
    };

    const _oldbold = String.prototype.bold;
    String.prototype.bold = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldbold.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldbold.apply(this, arguments);
    };

    const _oldcharAt = String.prototype.charAt;
    String.prototype.charAt = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldcharAt.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldcharAt.apply(this, arguments);
    };

    const _oldconcat = String.prototype.concat;
    String.prototype.concat = function () {
        const sources = [];
        for (let i = 0; i < arguments.length; i++) {
            arguments[i] = __convert_to_xssfinder_string_if_location(arguments[i]);
            if (__is_xssfinder_string(arguments[i])) {
                arguments[i].sources.forEach(e => sources.push(e));
            }
        }
        if (__is_xssfinder_string(this)) {
            this.sources.forEach(e => sources.push(e));
        }
        if (sources.length > 0) {
            const str = _oldconcat.apply(this.toString(), arguments);
            return new __xssfinder_String(str, { sources });
        }
        return _oldconcat.apply(this, arguments);
    };

    const _oldfixed = String.prototype.fixed;
    String.prototype.fixed = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldfixed.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldfixed.apply(this, arguments);
    };

    const _oldfontcolor = String.prototype.fontcolor;
    String.prototype.fontcolor = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldfontcolor.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldfontcolor.apply(this, arguments);
    };

    const _oldfontsize = String.prototype.fontsize;
    String.prototype.fontsize = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldfontsize.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldfontsize.apply(this, arguments);
    };


    const _olditalics = String.prototype.italics;
    String.prototype.italics = function () {
        if (__is_xssfinder_string(this)) {
            const str = _olditalics.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _olditalics.apply(this, arguments);
    };


    const _oldlink = String.prototype.link;
    String.prototype.link = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldlink.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldlink.apply(this, arguments);
    };

    const _oldmatch = String.prototype.match;
    String.prototype.match = function () {
        // TODO propagate taints of the regexp argument
        if (__is_xssfinder_string(this)) {
            const res = _oldmatch.apply(this.toString(), arguments);
            if (res === null) {
                return null;
            }
            for (let i = 0; i < res.length; i++) {
                res[i] = new __xssfinder_String(res[i], this);
            }
            return res;
        }
        return _oldmatch.apply(this, arguments);
    };

    // TODO propagate taints of the regexp argument
    const _oldmatchAll = String.prototype.matchAll;
    String.prototype.matchAll = function () {
        if (__is_xssfinder_string(this)) {
            const iterator = _oldmatchAll.apply(this.toString(), arguments);
            return (function* () {// (需要运行生成器函数,启动生成器)
                for (const array of iterator) {
                    for (let i = 0; i < array.length; i++) {
                        array[i] = new __xssfinder_String(array[i], this);
                    }
                    yield array;
                }
            })();
        }
        return _oldmatchAll.apply(this, arguments);
    };

    const _oldnormalize = String.prototype.normalize;
    String.prototype.normalize = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldnormalize.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldnormalize.apply(this, arguments);
    };

    // 'skr'.padEnd(7, 'r') => 'skrrrrr'
    const _oldpadEnd = String.prototype.padEnd;
    String.prototype.padEnd = function () {
        const sources = [];
        arguments[1] = __convert_to_xssfinder_string_if_location(arguments[1]);
        if (__is_xssfinder_string(arguments[1])) {
            arguments[1].sources.forEach(e => sources.push(e));
        }
        if (__is_xssfinder_string(this)) {
            this.sources.forEach(e => sources.push(e));
        }
        if (sources.length > 0) {
            const _str = _oldpadEnd.apply(this.toString(), arguments);
            return new __xssfinder_String(_str, { sources });
        }
        return _oldpadEnd.apply(this, arguments);
    };

    // 'good'.padStart(7, 'g') => 'ggggood'
    const _oldpadStart = String.prototype.padStart;
    String.prototype.padStart = function () {
        const sources = [];
        arguments[1] = __convert_to_xssfinder_string_if_location(arguments[1]);
        if (__is_xssfinder_string(arguments[1])) {
            arguments[1].sources.forEach(e => sources.push(e));
        }
        if (__is_xssfinder_string(this)) {
            this.sources.forEach(e => sources.push(e));
        }
        if (sources.length > 0) {
            const str = _oldpadStart.apply(this.toString(), arguments);
            return new __xssfinder_String(str, { sources });
        }
        return _oldpadStart.apply(this, arguments);
    };

    const _oldrepeat = String.prototype.repeat;
    String.prototype.repeat = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldrepeat.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldrepeat.apply(this, arguments);
    };

    const _oldreplace = String.prototype.replace;
    String.prototype.replace = function () {
        const sources = [];
        arguments[1] = __convert_to_xssfinder_string_if_location(arguments[1]);
        if (__is_xssfinder_string(arguments[1])) {
            arguments[1].sources.forEach(e => sources.push(e));
        }
        if (__is_xssfinder_string(this)) {
            this.sources.forEach(e => sources.push(e));
        }
        if (sources.length > 0) {
            const str = _oldreplace.apply(this.toString(), arguments);
            return new __xssfinder_String(str, { sources });
        }
        return _oldreplace.apply(this, arguments);
    };

    const _oldslice = String.prototype.slice;
    String.prototype.slice = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldslice.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldslice.apply(this, arguments);
    };

    const _oldsmall = String.prototype.small;
    String.prototype.small = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldsmall.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldsmall.apply(this, arguments);
    };

    const _oldsplite = String.prototype.split;
    String.prototype.split = function () {
        if (__is_xssfinder_string(this)) {
            const array = _oldsplite.apply(this.toString(), arguments);
            for (let i = 0; i < array.length; i++) {
                array[i] = new __xssfinder_String(array[i], this);
            }
            return array;
        }
        return _oldsplite.apply(this, arguments);
    };

    const _oldstrike = String.prototype.strike;
    String.prototype.strike = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldstrike.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldstrike.apply(this, arguments);
    };

    const _oldsub = String.prototype.sub;
    String.prototype.sub = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldsub.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldsub.apply(this, arguments);
    };

    const _oldsubstr = String.prototype.substr;
    String.prototype.substr = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldsubstr.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldsubstr.apply(this, arguments);
    };

    const _oldsubstring = String.prototype.substring;
    String.prototype.substring = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldsubstring.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldsubstring.apply(this, arguments);
    };

    const _oldsup = String.prototype.sup;
    String.prototype.sup = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldsup.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldsup.apply(this, arguments);
    };

    const _oldtoLocaleLowerCase = String.prototype.toLocaleLowerCase;
    String.prototype.toLocaleLowerCase = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldtoLocaleLowerCase.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldtoLocaleLowerCase.apply(this, arguments);
    };

    const _oldtoLocaleUpperCase = String.prototype.toLocaleUpperCase;
    String.prototype.toLocaleUpperCase = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldtoLocaleUpperCase.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldtoLocaleUpperCase.apply(this, arguments);
    };

    const _oldtoLowerCase = String.prototype.toLowerCase;
    String.prototype.toLowerCase = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldtoLowerCase.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldtoLowerCase.apply(this, arguments);
    };

    const _oldtoUpperCase = String.prototype.toUpperCase;
    String.prototype.toUpperCase = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldtoUpperCase.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldtoUpperCase.apply(this, arguments);
    };

    const _oldtrim = String.prototype.trim;
    String.prototype.trim = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldtrim.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldtrim.apply(this, arguments);
    };

    const _oldtrimEnd = String.prototype.trimEnd;
    String.prototype.trimEnd = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldtrimEnd.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldtrimEnd.apply(this, arguments);
    };

    const _oldtrimStart = String.prototype.trimStart;
    String.prototype.trimStart = function () {
        if (__is_xssfinder_string(this)) {
            const str = _oldtrimStart.apply(this.toString(), arguments);
            return new __xssfinder_String(str, this);
        }
        return _oldtrimStart.apply(this, arguments);
    };

    // skip String.prototype.toString, which is overwritten in __xssfinder_String
    // skip String.prototype.valueOf, which is overwritten in __xssfinder_String

    ///////////////////////////////////////////////
    // RegExp.prototype
    ///////////////////////////////////////////////

    const _oldregExpPrototypeExec = RegExp.prototype.exec;
    RegExp.prototype.exec = function () {
        const array = _oldregExpPrototypeExec.apply(this, arguments);
        if (array !== null && __is_xssfinder_string(arguments[0])) {
            for (let i = 0; i < array.length; i++) {
                array[i] = new __xssfinder_String(array[i], arguments[0]);
            }
        }
        return array;
    };

    ///////////////////////////////////////////////
    // global functions
    ///////////////////////////////////////////////

    const _olddecodeURI = decodeURI;
    decodeURI = function (URI) {
        URI = __convert_to_xssfinder_string_if_location(URI);
        if (__is_xssfinder_string(URI)) {
            const str = _olddecodeURI.apply(this, [URI.toString()]);
            return new __xssfinder_String(str, URI);
        }
        return _olddecodeURI.apply(this, arguments);
    };

    const _oldencodeURI = encodeURI;
    encodeURI = function (URI) {
        URI = __convert_to_xssfinder_string_if_location(URI);
        if (__is_xssfinder_string(URI)) {
            const str = _oldencodeURI.apply(this, [URI.toString()]);
            return new __xssfinder_String(str, URI);
        }
        return _oldencodeURI.apply(this, arguments);
    };

    const _olddecodeURIComponent = decodeURIComponent;
    decodeURIComponent = function (URI) {
        URI = __convert_to_xssfinder_string_if_location(URI);
        if (__is_xssfinder_string(URI)) {
            const str = _olddecodeURIComponent.apply(this, [URI.toString()]);
            return new __xssfinder_String(str, URI);
        }
        return _olddecodeURIComponent.apply(this, arguments);
    };

    const _encodeURIComponent = encodeURIComponent;
    encodeURIComponent = function (URI) {
        URI = __convert_to_xssfinder_string_if_location(URI);
        if (__is_xssfinder_string(URI)) {
            const str = _encodeURIComponent.apply(this, [URI.toString()]);
            return new __xssfinder_String(str, URI);
        }
        return _encodeURIComponent.apply(this, arguments);
    };

    const _oldunescape = unescape;
    unescape = function (escapedString) {
        escapedString = __convert_to_xssfinder_string_if_location(escapedString);
        if (__is_xssfinder_string(escapedString)) {
            const str = _oldunescape.apply(this, [escapedString.toString()]);
            return new __xssfinder_String(str, escapedString);
        }
        return _oldunescape.apply(this, arguments);
    };

    const _oldescape = escape;
    escape = function (string) {
        string = __convert_to_xssfinder_string_if_location(string);
        if (__is_xssfinder_string(string)) {
            const str = _oldescape.apply(this, [string.toString()]);
            return new __xssfinder_String(str, string);
        }
        return _oldescape.apply(this, arguments);
    };

    const _oldpostMessage = postMessage;
    postMessage = function (message) {
        if (__is_xssfinder_string(message)) {
            arguments[0] = message.toString();
        }
        return _oldpostMessage.apply(this, arguments);
    };

    ///////////////////////////////////////////////
    // window.localStorage
    // https://developer.mozilla.org/zh-CN/docs/Web/API/Window/localStorage
    ///////////////////////////////////////////////
    const _localStorage_getItem = window.localStorage.getItem;
    window.localStorage.getItem = function (keyname) {
        let sources = [];
        if (__is_xssfinder_string(keyname)) {
            keyname.sources.forEach(e => sources.push(e));
        }
        sources.push(__xssfinder_set_track_chian('window.localStorage.getItem("' + keyname + '")'));

        let val = _localStorage_getItem.apply(this, [keyname.toString()]);
        return parseObject(val, sources)
    };
    ///////////////////////////////////////////////
    // window.sessionStorage
    // https://developer.mozilla.org/zh-CN/docs/Web/API/Window/sessionStorage
    ///////////////////////////////////////////////
    const _sessionStorage_getItem = window.sessionStorage.getItem;
    window.sessionStorage.getItem = function (keyname) {
        let sources = [];
        if (__is_xssfinder_string(keyname)) {
            keyname.sources.forEach(e => sources.push(e));
        }
        sources.push(__xssfinder_set_track_chian('window.sessionStorage.getItem("' + keyname + '")'));

        let val = _sessionStorage_getItem.apply(this, [keyname.toString()]);
        return parseObject(val, sources)
    };
})();

/*********************************************/
// window.Storage
/*********************************************/

function parseObject(val, sources) {
    switch (typeof val) {
        case 'string':
            return new __xssfinder_String(val.toString(), { sources: sources });
        case 'number':
            // TODO custom number
            val.____xssfinder_String_flag = true;
            val['sources'] = [];
            sources.forEach(e => val['sources'].push(e));
            return val
        case 'boolean':
            val.____xssfinder_String_flag = true;
            val['sources'] = [];
            sources.forEach(e => val['sources'].push(e));
            return val
        case 'object':
            for (const key in val) {
                val[key] = parseObject(val, sources);
            }
            return val;
        case 'undefined':
            return val;
        case 'symbol':
            return val;
    }
}

/*********************************************/
// sinks
/*********************************************/


(function () {
    ///////////////////////////////////////////////
    // Range.prototype
    ///////////////////////////////////////////////

    const _rangeCreateContextualFragment = Range.prototype.createContextualFragment;
    Range.prototype.createContextualFragment = function (fragment) {
        if (__is_xssfinder_string_html(fragment)) {
            __xssfinder_push_dmo_vul(fragment.sources, 'Range.prototype.createContextualFragment()');
        }
        return _rangeCreateContextualFragment.apply(this, arguments);
    };

    ///////////////////////////////////////////////
    // document
    ///////////////////////////////////////////////

    const _documentWrite = document.write;
    document.write = function (...text) {
        for (let i = 0; i < text.length; i++) {
            if (__is_xssfinder_string_html(text[i])) {
                __xssfinder_push_dmo_vul(text[i].sources, 'document.write()');
            }
        }
        return _documentWrite.apply(this, arguments);
    };

    const documentWriteln = document.writeln;
    document.writeln = function (...text) {
        for (let i = 0; i < text.length; i++) {
            if (__is_xssfinder_string_html(text[i])) {
                __xssfinder_push_dmo_vul(text[i].sources, 'document.writeln()');
            }
        }
        return documentWriteln.apply(this, arguments);
    };

    ///////////////////////////////////////////////
    // global functions
    ///////////////////////////////////////////////

    const _eval = eval;
    eval = function (x) {
        if (__is_xssfinder_string_script(x)) {
            __xssfinder_push_dmo_vul(x.sources, 'eval()');
            // eval requires toString()
            try {
                return _eval.apply(this, [x.toString()]);
            } finally {
                return undefined;
            }
        }
        return _eval.apply(this, arguments);
    };

    const _setInterval = setInterval;
    setInterval = function (handler) {
        if (__is_xssfinder_string_script(handler)) {
            __xssfinder_push_dmo_vul(handler.sources, 'setTimeout()');
        }
        return _setInterval.apply(this, arguments);
    };

    const _setTimeout = setTimeout;
    setTimeout = function (handler) {
        if (__is_xssfinder_string_script(handler)) {
            __xssfinder_push_dmo_vul(handler.sources, 'setTimeout()');
        }
        return _setTimeout.apply(this, arguments);
    };

})();


// @asthook: +,+=
function __xssfinder_plus(left, right) {
    left = __convert_to_xssfinder_string_if_location(left);
    right = __convert_to_xssfinder_string_if_location(right);

    const sources = [];
    if (__is_xssfinder_string(left)) {
        left.sources.forEach(e => sources.push(e));
    }
    if (__is_xssfinder_string(right)) {
        right.sources.forEach(e => sources.push(e));
    }
    if (sources.length > 0) {
        return new __xssfinder_String('' + left + right, { sources });
    }

    try {
        return left + right;
    } catch (e) {
        return left.toString() + right.toString();
    }
}

// @asthook: object.key || object[key]
function __xssfinder_get(object, key) {
    if (object === window.location) {
        switch (key) {
            case 'hash':
            case 'href':
            case 'pathname':
            case 'search':
                return new __xssfinder_String(object[key], {
                    sources: [__xssfinder_set_track_chian('window.location.' + key)],
                });
        }
    } else if (object === document) {
        switch (key) {
            case 'documentURI':
            case 'baseURI':
            case 'URL':
            case 'cookie':
                return new __xssfinder_String(object[key], {
                    sources: [__xssfinder_set_track_chian('document.' + key)],
                });
            case 'referrer': // referrer - https://developer.mozilla.org/zh-CN/docs/Web/API/Document/referrer
                let referrer = object[key];
                if (referrer === '') {
                    referrer = 'https://zznq.imipy.com';
                }
                return new __xssfinder_String(referrer, {
                    sources: [__xssfinder_set_track_chian('document.' + key)],
                });
        }
    } else if (object === window) {
        switch (key) {
            case 'status': // window.status - https://developer.mozilla.org/en-US/docs/Web/API/Window/status
                if (window.status !== '' && window.status.startsWith("__xssfinder")) {
                    let v = window['__xssfinder_status'];
                    v.sources.push(__xssfinder_set_track_chian('window.status'))
                    return v
                }
                return window.status
            case 'name':
                return new __xssfinder_String(object[key], {
                    sources: [__xssfinder_set_track_chian('window.' + key)],
                });
        }
    } else if (object === window.localStorage) {
        // window.localStorage - https://developer.mozilla.org/zh-CN/docs/Web/API/Window/localStorage
        let sources = [__xssfinder_set_track_chian('window.localStorage["' + key + '"]')]
        return parseObject(object[key], sources);
    } else if (object === window.sessionStorage) {
        // window.sessionStorage - https://developer.mozilla.org/zh-CN/docs/Web/API/Window/sessionStorage
        let sources = [__xssfinder_set_track_chian('window.sessionStorage["' + key + '"]')]
        return parseObject(object[key], sources);
    }
    return object[key];
}

// @asthook: object.key = value || object[key] = value
function __xssfinder_put(object, key, value) {
    if (object[key] === window.location && __is_xssfinder_string_script(value)) {
        // kill navigation
        return;
    } else if (object === window.location && key === 'href' && __is_xssfinder_string_script(value) && value.toString() !== object[key]) {
        // kill navigation
        return;
    }

    // window.status - https://developer.mozilla.org/en-US/docs/Web/API/Window/status
    if (object === window && key === 'status' && __is_xssfinder_string(value)) {
        object['__xssfinder_status'] = value
        object['status'] = "__xssfinder" + value.toString()
        return;
    }


    if (object instanceof Element && __is_xssfinder_string_html(value)) {
        if (key === 'innerHTML' || key === 'outerHTML') {
            __xssfinder_push_dmo_vul(value.sources, 'Element.' + key);
        }
    } else if (object instanceof HTMLScriptElement && __is_xssfinder_string_script(value)) {
        if (key === 'text' || key === 'textContent' || key === 'innerText') {
            __xssfinder_push_dmo_vul(value.sources, 'HTMLScriptElement.' + key);
        }
    } else if (object instanceof HTMLScriptElement
        && key === 'src'
        && __is_xssfinder_string_url(value)) {
        __xssfinder_push_dmo_vul(value.sources, 'HTMLScriptElement.src');

    } else if (object instanceof HTMLEmbedElement
        && key === 'src'
        && __is_xssfinder_string_url(value)) {
        __xssfinder_push_dmo_vul(value.sources, 'HTMLEmbedElement.src');

    } else if (object instanceof HTMLIFrameElement
        && key === 'src'
        && __is_xssfinder_string_script(value)) {
        __xssfinder_push_dmo_vul(value.sources, 'HTMLIFrameElement.src');

    } else if (object instanceof HTMLAnchorElement
        && key === 'href'
        && __is_xssfinder_string_script(value)) {
        __xssfinder_push_dmo_vul(value.sources, 'HTMLAnchorElement.href');

    } else if (object instanceof HTMLFormElement
        && key === 'action'
        && __is_xssfinder_string_script(value)) {
        __xssfinder_push_dmo_vul(value.sources, 'HTMLFormElement.action');

    } else if (object instanceof HTMLInputElement
        && key === 'formAction'
        && __is_xssfinder_string_script(value)) {
        __xssfinder_push_dmo_vul(value.sources, 'HTMLInputElement.formAction');

    } else if (object instanceof HTMLButtonElement
        && key === 'formAction'
        && __is_xssfinder_string_script(value)) {
        __xssfinder_push_dmo_vul(value.sources, 'HTMLButtonElement.formAction');

    } else if (object instanceof HTMLObjectElement
        && key === 'data'
        && __is_xssfinder_string_data_html(value)) {
        __xssfinder_push_dmo_vul(value.sources, 'HTMLObjectElement.data');
    }
    return object[key] = value;
}

// @asthook: function
// example => `const sum = new Function('a', 'b', 'return a + b');`
function __xssfinder_new_Function() {
    const f = new Function(...arguments);
    const _code = arguments[arguments.length - 1];
    if (__is_xssfinder_string_script(_code)) {
        __xssfinder_push_dmo_vul(_code.sources, 'new Function()');
        f.__dombasedxssfinder_str = _code;
    }
    return f;
}

// @asthook: ==
function __xssfinder_equal(left, right) {
    if (__is_xssfinder_string(left)) {
        left = left.toString();
    }
    if (__is_xssfinder_string(right)) {
        right = right.toString();
    }
    return left == right;
}

// @asthook: !=
function __xssfinder_notEqual(left, right) {
    if (__is_xssfinder_string(left)) {
        left = left.toString();
    }
    if (__is_xssfinder_string(right)) {
        right = right.toString();
    }
    return left != right;
}

// @asthook: ===
function __xssfinder_strictEqual(left, right) {
    if (__is_xssfinder_string(left)) {
        left = left.toString();
    }
    if (__is_xssfinder_string(right)) {
        right = right.toString();
    }
    return left === right;
}

// @asthook: !==
function __xssfinder_strictNotEqual(left, right) {
    if (__is_xssfinder_string(left)) {
        left = left.toString();
    }
    if (__is_xssfinder_string(right)) {
        right = right.toString();
    }
    return left !== right;
}

// @asthook: typeof
function __xssfinder_typeof(o) {
    if (__is_xssfinder_string(o)) {
        return 'string';
    }
    return typeof o;
}

// @asthook: object.key(...arguments) || object[key](...arguments)
function __xssfinder_property_call(object, key, ...arguments) {
    if (object[key] === window.location.assign) {
        // cannot overwrite, replace it when called.
        return (function (url) {
            if (__is_xssfinder_string_script(url)) {
                // kill navigation
                return;
            }
        }).apply(object, arguments);
    } else if (object[key] === window.location.replace) {
        // cannot overwrite, replace it when called.
        return (function (url) {
            if (__is_xssfinder_string_script(url)) {
                // kill navigation
                return;
            }
        }).apply(object, arguments);
    }

    if (object instanceof Element && key === 'setAttribute') {
        const _elementSetAttribute = object[key];
        return (function (qualifiedName, value) {
            if (qualifiedName.startsWith('on') && __is_xssfinder_string_script(value)) {
                __xssfinder_push_dmo_vul(value.sources, `Element.setAttribute('${qualifiedName}')`);
            } else if (this instanceof HTMLScriptElement && qualifiedName === 'src' && __is_xssfinder_string_url(value)) {
                __xssfinder_push_dmo_vul(value.sources, 'HTMLScriptElement.setAttribute(\'src\')');
            } else if (this instanceof HTMLEmbedElement && qualifiedName === 'src' && __is_xssfinder_string_url(value)) {
                __xssfinder_push_dmo_vul(value.sources, 'HTMLEmbedElement.setAttribute(\'src\')');
            } else if (this instanceof HTMLIFrameElement && qualifiedName === 'src' && __is_xssfinder_string_script(value)) {
                __xssfinder_push_dmo_vul(value.sources, 'HTMLIFrameElement.setAttribute(\'src\')');
            } else if (this instanceof HTMLAnchorElement && qualifiedName === 'href' && __is_xssfinder_string_script(value)) {
                __xssfinder_push_dmo_vul(value.sources, 'HTMLAnchorElement.setAttribute(\'href\')');
            } else if (this instanceof HTMLFormElement && qualifiedName === 'action' && __is_xssfinder_string_script(value)) {
                __xssfinder_push_dmo_vul(value.sources, 'HTMLFormElement.setAttribute(\'action\')');
            } else if (this instanceof HTMLInputElement && qualifiedName === 'formaction' && __is_xssfinder_string_script(value)) {
                __xssfinder_push_dmo_vul(value.sources, 'HTMLInputElement.setAttribute(\'formaction\')');
            } else if (this instanceof HTMLButtonElement && qualifiedName === 'formaction' && __is_xssfinder_string_script(value)) {
                __xssfinder_push_dmo_vul(value.sources, 'HTMLButtonElement.setAttribute(\'formaction\')');
            } else if (this instanceof HTMLObjectElement && qualifiedName === 'data' && __is_xssfinder_string_data_html(value)) {
                __xssfinder_push_dmo_vul(value.sources, 'HTMLObjectElement.setAttribute(\'data\')');
            }
            _elementSetAttribute.apply(this, arguments);
        }).apply(object, arguments);
    } else if (object instanceof Element && key === 'addEventListener') {
        const _elementAddEventListener = object[key];
        return (function (type, listener) {
            if (type === 'click' && listener && listener.__dombasedxssfinder_str && __is_xssfinder_string_script(listener.__dombasedxssfinder_str)) {
                __xssfinder_push_dmo_vul(listener.__dombasedxssfinder_str.sources, 'Element.addEventListener(\'click\')');
            }
            _elementAddEventListener.apply(this, arguments);
        }).apply(object, arguments);
    }

    return object[key](...arguments);
}

// @asthook: func(...arguments)
function __xssfinder_call(func, ...arguments) {
    if (func === window.location.assign) {
        // cannot overwrite, replace it when called.
        func = function (url) {
            if (__is_xssfinder_string_script(url)) {
                // kill navigation
                return;
            }
        };
    } else if (func === window.location.replace) {
        // cannot overwrite, replace it when called.
        func = function (url) {
            if (__is_xssfinder_string_script(url)) {
                // kill navigation
                return;
            }
        };
    }

    return func(...arguments);
}