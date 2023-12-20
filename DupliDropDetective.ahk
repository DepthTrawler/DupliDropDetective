#Requires AutoHotkey v2.0
Duplicates := Map()
FileSizes := Map()
JsonObj := Map()
Output := A_InitialWorkingDir "\duplicates.json"
TotalBytes := 0
TotalItems := 0
for Arg in A_Args {
	if !InStr(FileGetAttrib(Arg), "D") {
		throw Error("Path points to a file.", -1, '"' Arg '"')
	}
	loop files, Arg "\*", "FR" {
		Bytes := FileGetSize(A_LoopFileFullPath)
		TotalItems++
		; Ignore 0 byte files.
		if !Bytes {
			continue
		}
		TotalBytes += Bytes
		if !FileSizes.Has(Bytes) {
			FileSizes.Set(Bytes, Array(A_LoopFileFullPath))
			continue
		}
		FileSizes.Get(Bytes).Push(A_LoopFileFullPath)
	}
}
for Size, Coll in FileSizes {
	; This collection contains only a single file, ignore it.
	if Coll.Length = 1 {
		FileSizes.Delete(Size)
		continue
	}
	; Begin hashing files of the same size.
	for Path in Coll {
		Duplicate := Map(
			"filePath", Path,
			"lastModified", FileGetTime(Path, "M")
		)
		Hash := SHA256(Path)
		if !Duplicates.Has(Hash) {
			Duplicates.Set(Hash, Map("file1", Duplicate))
			continue
		}
		Duplicates.Get(Hash).Set("file" Duplicates.Get(Hash).Count + 1, Duplicate)
	}
}
for Hash, Coll in Duplicates.Clone() {
	; This is not a duplicate.
	if Coll.Count < 2 {
		Duplicates.Delete(Hash)
	}
}
JobSummary := Map(
	"dirsProcessed", A_Args,
	"duplicatesFound", Duplicates.Count,
	"filesProcessed", TotalItems,
	"totalBytesProcessed", TotalBytes
)
JsonObj.Set(
	"jobSummary", JobSummary,
	"hash", Duplicates
)
FileObj := FileOpen(Output, "W")
JsonObj := JSON.Dump(JsonObj, Indent := "`t")
FileObj.Write(JsonObj)
FileObj.Close()
ExitApp()

; Credit: anonymous1184 (https://github.com/anonymous1184)
SHA256(FilePath) {
	local FileObj := FileOpen(FilePath, "R")
	DllCall("advapi32.dll\CryptAcquireContext",
		"Ptr*", &Key := 0,
		"Ptr", 0,
		"Ptr", 0,
		"UInt", 0x00000018,
		"UInt", 0xF0000000
	)
	DllCall("advapi32.dll\CryptCreateHash",
		"Ptr", Key,
		"UInt", 0x0000800C,
		"UInt", 0,
		"UInt", 0,
		"Ptr*", &HashObj := 0
	)
	Data := Buffer(1024 ** 2)
	while !FileObj.AtEoF {
		BytesRead := FileObj.RawRead(Data)
		DllCall("advapi32.dll\CryptHashData",
			"Ptr", HashObj,
			"Ptr", Data,
			"UInt", BytesRead,
			"UInt", 0
		)
	}
	FileObj.Close()
	DllCall("advapi32.dll\CryptGetHashParam",
		"Ptr", HashObj,
		"UInt", 2,
		"Ptr", 0,
		"UInt*", &Data := 0,
		"UInt", 0
	)
	Data := Buffer(Data)
	DllCall("advapi32.dll\CryptGetHashParam",
		"Ptr", HashObj,
		"UInt", 2,
		"Ptr", Data,
		"UInt*", Data.Size,
		"UInt", 0
	)
	DllCall("advapi32.dll\CryptDestroyHash", "Ptr", HashObj)
	DllCall("advapi32.dll\CryptReleaseContext", "Ptr", Key)
	Hash := Buffer(Data.Size * 4 + 1)
	DllCall("crypt32.dll\CryptBinaryToString",
		"Ptr", Data,
		"UInt", Data.Size,
		"UInt", 0x4000000c,
		"Ptr", Hash,
		"UInt*", Hash.Size
	)
	return StrGet(Hash)
}

; Credit: G33kDude https://github.com/G33kDude & CloakerSmoker https://github.com/CloakerSmoker
Class JSON {
	static __New() {
		this.Library := this._LoadLib()
		this.Library.ObjTrue := ObjPtr(this.True)
		this.Library.ObjFalse := ObjPtr(this.False)
		this.Library.ObjNull := ObjPtr(this.Null)
		this.Library.GetMap := ObjPtr(Map)
		this.Library.GetArray := ObjPtr(Array)
		this.Library.CastString := ObjPtr(this.CastString)
	}

	static _LoadLib() => this.C

	static Dump(Obj, Indent := 0) {
		if !IsObject(Obj) {
			throw Error("Input must be an Object")
		}
		if !RegExMatch(Indent, "^(?<Indent>\d*|`t)$", &Match) {
			throw ValueError("Parameter #2 of " A_ThisFunc " is invalid.", -1, '"' Indent '"')
		}
		B1 := Buffer(A_PtrSize)
		Size := 0
		this.Library._Dump(ObjPtr(Obj), 0, &Size, !!Indent, 0)
		B2 := Buffer(Size * 5 + 2, 0)
		NumPut("Ptr", B2.Ptr, B1)
		this.Library._Dump(ObjPtr(Obj), B1, &Size, !!Indent, 0)
		JSON := StrGet(B2, "UTF-16")
		if Indent && Match.Indent != "`t" {
			if Indent > 10 {
				Indent := 10
			}
			loop Indent {
				Indentation .= "`s"
			}
			return RegExReplace(JSON, "S)\t", Indentation)
		}
		return JSON
	}

	static Load(JSON) {
		B1 := Buffer(A_PtrSize)
		B2 := Buffer(24)
		JSON := " " JSON
		NumPut("Ptr", StrPtr(JSON), B1)
		if Result := this.Library._Load(B1, B2) {
			throw Error(
				"Failed to parse JSON (" Result ")",
				-1,
				Format(
					"Unexpected character at position {1}: '{2}'",
					(NumGet(B1, 'UPtr') - StrPtr(JSON)) // 2,
					Chr(NumGet(NumGet(B1, 'UPtr'), 'Short'))
				)
			)
		}
		Result := ComValue(0x0000400C, B2.Ptr)[]
		if IsObject(Result) {
			ObjRelease(ObjPtr(Result))
		}
		return Result
	}

	static BoolsAsInts {
		Get => this.Library._BoolsAsInts
		Set => this.Library._BoolsAsInts := value
	}

	static CastString := Format.Bind("{}")

	static EscapeUnicode {
		Get => this.Library._EscapeUnicode
		Set => this.Library._EscapeUnicode := value
	}

	static False {
		Get => {Value: false, Name: "false"}
	}

	static Null {
		Get => {Value: "", Name: "null"}
	}

	static NullsAsStrings {
		Get => this.Library._NullsAsStrings
		Set => this.Library._NullsAsStrings := value
	}

	static True {
		Get => {Value: true, Name: "true"}
	}

	static Version := "1.6.0-git-dev"

	class C {
		static Code := Buffer(6960)
		static CodeB64 := (
			"a7gAQVdBVkFVQVQAVVdWU0iB7GgAAgAASI0FiBYBADCJ00SJTCRcQEiJzUSKbAEchAgkkAAAXIsBTIlAxkiNlCSMATSJQFQkKEG5AQEUjYAVHhUA"
			"AEyNA04Qx0QkIAAMAP9QBCiLA1aD+v91LgUASj4AumYPvgKEIMAPhGIEADiF2wB0D0iLC0yNQQACTIkDZokB6wAC/wZI/8Lr2SBFMeS5BgA6RTEA"
			"yUUxwESJ4EgQjbwkmAAQTI20hCSwAXTHhCTAAWbZAADzqwIrAL/uAIcBKaLIAqGEJKACFoQCOQcBDwE5AEzzq0iLRbUADIwCFGYAJQEQCAARQEwk"
			"MEiJ6QEh4L0EMrgEMoQ3AngAcUCBCQUBBDgBBEyJdCQo4wF8AQ//UDCAMQVfgDVYjQVggEsECMCBQ+j3hEsCMgA2+ItPAbIBCYRTuwBIgLYwBjsE"
			"qwEcEAA474FfASSAX6RHhIIbCSSCVA3AEyjABQALTI0dtQ4UyR8AJIEGTImcJP4YwAHCI4QhgR+BE4Mf20UlwBVdwBVmg4NoA3XKCkAC0EEKdV4B"
			"BQE9MwMFAlp1TgEFAR4DdUoQQAIwAQVBvMCqAKR1OQCU7RMHlBFBsOEalOsGQbwBEEA8QDpCQEVAQYP8AgM6TFuEBcGYGIATQbQAgRWLEEAoD4WB"
			"SEyJREQkKMBDTYnwgB8o3hJERMAIg8LGvtAAR4EOdYW+Q0gqZwFQVyqDJzDvAA8DvwIpQW2MAgVCZBBaSnxBrkxHW+nFgnQ9Vv8AKYFv6IJt6YTs"
			"iZNAWCEcifcCeTHSgDi/IQQiXYYYhA+jRiJmlGMQ3aAFQKEwxD8BIANBSWABLiBgAUEDYQQ4ZARMib604gbEBnVoQBhhDwPFi89gKKQWQEeAKP4R"
			"Q0dhNEgJdFvjKXQbdyndBYUmSeA1idpIiawZogHoT6AxoAYPhLACBwEqA0iNUAJIAIkTZscAIgDpFp5hAkAKGwBDAUiLIBMZwIPgIHJKAgCDwHtI"
			"iQtmiUICwQuAfCRcIZ+uUWASD4WpxkpYYBMxYO1FD7b1QidBSrhjQALhN7wkcGVOwwGIXcsBoMsBwQbGAYQCC0jdwE9wgQEBCYEBeIEBIjIVgAFg"
			"gQHQJANo6bc7wSjgGB1KI8Ai4yZ144jpSv8AAAbr7GEqFaENAwAZBWBWvCTAEUE0D4SboAGF7Q/EhIQjVg+EUQEB6SUSLGEgqhBgRITtDwSFTsAD"
			"QY1EJP9Ag/gBD4aSoAGLUWMVZoP4gAsBIDtI8GOEJHihCCAzwUaBjxPhACM06LXAKf/FSEKLQRuLfCRoQ2BI0IuMJEgBK9KhTeEk9AxAAQeowhGg"
			"l6SgASrgDEAPKIxiBCEEwU11oQlwwVHgBFwi2kQHmJHgAA8QlEIHDylEbNXgA1gEB2ABB9gIBwIs3IsBxAkiXQBXKPhZYikwEZQkSIAFAFmJxwKF"
			"gICI/v//SJiE6TMgLP8G6behAaVgNRp1NesuADXvgSykhJtgBesfoQUwtQUY/8c7wKrADQ+PbQEhC40VCg8AAOs64GAI2WAeQUkhMnUlXVEEEQww"
			"wjNQGmBQAumC1hE+g/gUdUivAm+kAoAcoQIEHPSABqIizUsig6s1wtOCfw5CBQk8dS0vPC88AAvxBetOxZADTpMDCHUqISFoB7ItICjrYS8UKRQE"
			"IRR4SA+/tDQEKKVBYyjo7jTzC68O0QMvkQGgB5gBIjqSL4QU/WEWUASBQgFAAiAA6QIQASSLBnAC/8ARAkXCgIkG6e78///SFGYN0QdhMOkEYAKx"
			"EA8GhQMTYwFIOw27C6myEmsNsG4npWPhAARXvxKmY2ADZGMDOWoDqqtvA2wDPWMDCGoDc28DR2kDgBkxJkWJ8TMU/wLAcEcg6KL1///E6TiTDgh1"
			"GCUNhBoShBAc6RqBBY0Vn8IM0hwFD4Xx9lMRNXF4b/IPEPVCxGCANyjjZGVBaQ1DCqOUgQMxQD1xAAVmReECEWmSOYsB/3OUoASjR5VvAQVPabVw"
			"kQHA8g8RhCQIAzzxSAiUJPBBNIsUAmZAhdIPhEn7nxKJghGSEoPAAuvPjym3jykUIXQSrLARUQMUPTRk3vpBW+nXYACnPAkMdRAFMVAO/1AQ64oU"
			"0hcOVQH/FXtwEh/XWAQDkhUOA1EB/xVKL4EVhFczAjVvupABdTXV0QlzP3J9NHJaPw85DzYjMg8gAiwvAkxMfZUlMAdJMAfr5EAD3f8SBgAYgcQR"
			"y1teXwBdQVxBXUFeQThfw5AKAJbNYZtJuIQAJhMeZscCFIAfAMtIidZIx0IIAWMhE2aLCmaD+RAgD4f7Mq7ASNMA6KgBdAlIg8IJcRfr3cABWw+F"
			"u78RaEAqYGnzxuABIijQEYMsiRNgK6ElgFO1vRMEAIAoJ1QkaEjBxOUJNCdMjaQzyQ8nWceySIsgghJTVFDYjVgFgQl0fjOcTIB2YKhIiwcQA1zD"
			"afkVLSMX2NAjZosIwQ13FABIiepI0+qA4kWSDcCQDQPr4JABXQgPhLyREYXJD4QCs3IE8kiJ2ei7U4BjgGqFk+IfBzM5TNSJZPGvtMILi2EJQAf9"
			"ADSoRNKxADHXBNNhAX81BYUAMPwOZoM+CXWgHkiLTggkKRIXCyYdFAv3DHbiUAAsD0yEMeAwIByDyPBGOjBdD4XyEHWEG2bHhAYJ4Ax+COkCQAEh"
			"4AIiD4UXgu5CAoMgAsBaA0iJRghgAhAIAOnkkm75ew/chQ6QD38ecB74oQV9HnK/fx7B538efx54Hqxjcx62DQ+GWODxkAB9WA+E7ZEAsRnkIwEi"
			"mA+EVpAA8A7pB1ENgIXJdPNMjUDyM0CD+VwPhQ2CSUgCArECdSZmx0L+GiIgDMDSDnERiwNMAI1C/hu3AGaLCGaD+SJ1QL/p5gAAAACgXAB1CGbH"
			"Qv5cABTr0gBoLwNoLwDrCsQANGIDNAgA67aFADRmAzQMAOuoABpCbgMaCgDrmgAaciEDGg0A64wAGnR1AgsBGgkA6Xv//0L/ACB1D4VDABJIQIPA"
			"BEG5BAB4SAyJAwEhAIGLQv5MAIsDweAEZolCAP5mQYsIRI1RANBmQYP6CXcFoEQB0OskAA+/AQ8ABXcGjUQIyesKEwAQnwIQD4fu/gT//wAUqUmD"
			"wAIBAT9MiQNB/8l1CKrpCgF3iUr+6QIBAXaLVghMicEBAH0CSCnRiUr8CGZBx4NB6eECAAAAjUHQZoP4CRBBD5bAAFUtD5QAwEEIwA+EuAFBgE7H"
			"BhQAugAEABBIx0YIAAMASIuAA2aDOC11C4ImWIPK/4AigQmLgKX4CDB1DoYTgwMC6xA2g+gxAAsID4cCRQBUSIsLSA+/EAFEjUiBb/kJdwAXTGtO"
			"CApIg4DBAkiJC0mNgHZASIlGCOvXgzEuhHQUAiwIg+HfgEsgRXRW6fACLMACBEG5AkmJA/JIDwQqRoC8BgUA8g8IEUYIADFmiwGDBOgwAWh3wEVr"
			"yYQKmIEv8g8qwIAxAPJBDyrJ8g9eQMHyD1hGCEIM6wbMAjKAY4M+FHUQhw8UQSCBRXQJRTHBR5grdQdEDMAGMckAPgGEGw+HYP3//0xVQCBBhyAP"
			"QCBJACCYAEyJCwHB6+FFBDHJwVUARDnJdAAIa8AKQf/B6wLzQCfI8g8QRgggRYTAdAbBJ+sEmPIPWUApQCCLDgAdAhQAVg+vVghIiTBWCOktABCC"
			"IgUPbIX8wAKAD8KACwQ06QbpwW3BoFNIjQ0kIQCbZg++AQAWGEgAixNI/8FmOwJQD4W2/AGjwkAxEyDr4IA9xoEkdBJNgD0DAnqBA+nGwcfHJAYJ"
			"gHwNJoCJ6auRA8xmdU0AFtADEhZqXQsWbQIWDwYWQYbrSnBFFbBAB+tYwdIPRIUkAQ6NDX+TFQaFixU2wytIiwWtACatgBMIAIPAchZFFmYACAhI"
			"iU6AbwH/UAgQMcDp1MKL+kjTAOqA4gEPhJn7E4JxoTjpfWABTIniAEiJ2ei/+P//YIXAD4WXwQMlPyCUdxgoB3wnB+vcoAPQOg+FaUYC8oAIAAMU"
			"6HfkCE/iCJQkoAGgD0mJ8EiJ6egmzAAWRwt2K6AALA9EhHCidBODyICFOhh9dSlkHcMZiW4ITOk5AQSlEHTUJRC1EEiBxLCAC1teX4BdQVzDkJCQ"
			"ISP/CQD9AR8AHwAfAB8AHwAfAD8fAB8AHwAfAB8ABwAwMQAyMzQ1Njc4OUBBQkNERUagQwAAYQBzAE0AZQCAdABoAG8AZKAEACJVbmtub3duAF9P"
			"YmplY3RfoAAAUAB1oARoYAMCUyIFAABPAHcAKm7gAnJgBnBgAwAAil8gAEVgAnUAbaABwA0KAAkAIgUIJgoAVHlwZV8AdHIAdWUAZmFsc2UgAG51"
			"bGzHA1ZhHGx14APoDQsAU0iBBuzBW0SyiwFMicMgSImUJLihAY1UICRUTI2EgwGJVAAkKDHSSImMJGEhVsdEJFThB+AAIOHhAP9QKIsgqoMDoKQ1"
			"YQdYIK5IAASiDmaJQEQkcEiLQ4CzhAwkiAACYX5EJHhIFovkCwAFYCLPiYQk7pCiDwEGQARYoBKhCCBvW6YQ8ABAwgKAADiFADCTBQkRev9QEFw7"
			"CYBuZItLc0QQkNA2sQ5bA4E2BABXVlNIg+yQMEG7E4ABuwozEFBIhcBmcAQuUT/SAEyNTCQGeTRBFLsUwAG/MQZImYkE/kSQQvf7KdZmAEOJdFn+"
			"Sf/LATADdeaD6QJIYwLBsANEBi0A6xhESJljAoPCMHACFAJZZALoSGPJSAEIyUwB0GcBZoXAAHQdTYXSdA9JAIsSTI1KAk2JYApmiQLrgICwcsGI"
			"AuvbQBSDxDAgQiNhC9EKIEiJcATSdIARSIsCSI1IkEQACmbHACIA6ymJMAPrJIBrInUxAQJqJgMCBNABXKATUAJAxAIiUAXDAmYgTJAICNTpUmAf"
			"QYMAAkTr6WADXHUcYQPvtW8DAvCVx6GAEwLNHwKgAmIA66UQAgwTAoKrHwICZgDrgxACKAp1HxECiR8CAm4IAOleEpf4DXUjMUACD4RgklWOAnIA"
			"1Ok1gwIJhAI3jwKBAhB0AOkMkAGAPbIA+v//AHQLjUgC4CBbXncR6zyNREiBoAAhdgZQBB8Udy0xCRcfBAJ1AATrBBESD7cL6E4dgXW8sZDAAvBr"
			"CkyNiEkCTAEbAemlYAE58BfpneQB3hkTHcQgBeknkOAcGDHATI0MHbNhbKAmCEmJyghmwekgB+IPZkcAD74UE2ZFiRQIQUj/UCD4BHXhKrgQdgDx"
			"BRXgB2ZFQIsUQUyNWTAIGhBmRIkRNAboAXMC3VIjGMM="
		)

		static __New() {
			if A_PtrSize * 8 != 64 {
				throw OSError("This function is not supported on this system. Please use 64-bit AutoHotkey.")
			}
			; MCL standalone loader https://github.com/G33kDude/MCLib.ahk
			; Copyright (c) 2023 G33kDude, CloakerSmoker (CC-BY-4.0)
			; https://creativecommons.org/licenses/by/4.0/
			Success := DllCall("crypt32.dll\CryptStringToBinary",
				"Str", this.CodeB64,
				"UInt", 0,
				"UInt", 0x00000001,
				"Ptr", B := Buffer(3980),
				"UInt*", B.Size,
				"Ptr", 0,
				"Ptr", 0,
				"UInt"
			)
			if !Success {
				throw Error("Failed to convert base64 string to binary")
			}
			StatusCode := DllCall("ntdll.dll\RtlDecompressBuffer",
				"UShort", 0x00000102,
				"Ptr", this.Code,
				"UInt", this.Code.Size,
				"Ptr", B,
				"UInt", B.Size,
				"UInt*", &UncompressedSize := 0,
				"UInt"
			)
			if StatusCode {
				throw Error("Failed to decompress the buffer", -1, Format("0x{:08x}", StatusCode))
			}
			if !Module := DllCall("kernel32.dll\GetModuleHandle", "Str", "oleaut32", "Ptr") {
				throw Error("Failed to load oleaut32.dll: " OSError().Message)
			}
			if !SysFreeString := DllCall("kernel32.dll\GetProcAddress", "Ptr", Module, "AStr", "SysFreeString", "Ptr") {
				throw Error("Failed to obtain address of SysFreeString from oleaut32.dll: " OSError().Message)
			}
			NumPut("Ptr", SysFreeString, this.Code, 5744)
			Success := DllCall("kernel32.dll\VirtualProtect",
				"Ptr", this.Code,
				"Ptr", this.Code.Size,
				"UInt", 0x40,
				"UInt*", 0,
				"UInt"
			)
			if !Success {
				throw OSError(A_LastError)
			}
		}

		static _Dump(pObjIn, ppszString, pcchString, bPretty, iLevel) {
			DllCall(this.Code.Ptr + 0,
				"Ptr", pObjIn,
				"Ptr", ppszString,
				"Int*", pcchString,
				"Int", bPretty,
				"Int", iLevel,
				"CDecl Ptr"
			)
		}

		static _Load(ppJson, pResult)  {
			return DllCall(this.Code.Ptr + 3296,
				"Ptr", ppJson,
				"Ptr", pResult,
				"CDecl Int"
			)
		}

		static _BoolsAsInts {
			Get => NumGet(this.Code.Ptr + 5344, "Int")
			Set => NumPut("Int", value, this.Code.Ptr + 5344)
		}

		static _EscapeUnicode {
			Get => NumGet(this.Code.Ptr + 5360, "Int")
			Set => NumPut("Int", value, this.Code.Ptr + 5360)
		}

		static _NullsAsStrings {
			Get => NumGet(this.Code.Ptr + 5376, "Int")
			Set => NumPut("Int", value, this.Code.Ptr + 5376)
		}

		static CastString {
			Get => NumGet(this.Code.Ptr + 5392, "Ptr")
			Set => NumPut("Ptr", value, this.Code.Ptr + 5392)
		}

		static GetArray {
			Get => NumGet(this.Code.Ptr + 5408, "Ptr")
			Set => NumPut("Ptr", value, this.Code.Ptr + 5408)
		}

		static GetMap {
			Get => NumGet(this.Code.Ptr + 5424, "Ptr")
			Set => NumPut("Ptr", value, this.Code.Ptr + 5424)
		}

		static ObjFalse {
			Get => NumGet(this.Code.Ptr + 5440, "Ptr")
			Set => NumPut("Ptr", value, this.Code.Ptr + 5440)
		}

		static ObjNull {
			Get => NumGet(this.Code.Ptr + 5456, "Ptr")
			Set => NumPut("Ptr", value, this.Code.Ptr + 5456)
		}

		static ObjTrue {
			Get => NumGet(this.Code.Ptr + 5472, "Ptr")
			Set => NumPut("Ptr", value, this.Code.Ptr + 5472)
		}
	}
}