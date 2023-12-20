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
	FileObj := FileOpen(FilePath, "R")
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
class JSON {
		static __New() {
		this.lib := this._LoadLib()
		this.lib.objTrue := ObjPtr(this.True)
		this.lib.objFalse := ObjPtr(this.False)
		this.lib.objNull := ObjPtr(this.Null)
		this.lib.fnGetMap := ObjPtr(Map)
		this.lib.fnGetArray := ObjPtr(Array)
		this.lib.fnCastString := ObjPtr(this.fnCastString)
	}

	static _LoadLib() {
		return this.MyC
	}

	static Dump(obj, pretty := 0) {
		if !IsObject(obj) {
			throw Error("Input must be object")
		}
		size := 0
		this.lib.dumps(ObjPtr(obj), 0, &size, !!pretty, 0)
		buf := Buffer(size*5 + 2, 0)
		bufbuf := Buffer(A_PtrSize)
		NumPut("Ptr", buf.Ptr, bufbuf)
		this.lib.dumps(ObjPtr(obj), bufbuf, &size, !!pretty, 0)
		return StrGet(buf, "UTF-16")
	}

	static Load(json) {
		_json := " " json ; Prefix with a space to provide room for BSTR prefixes
		pJson := Buffer(A_PtrSize)
		NumPut("Ptr", StrPtr(_json), pJson)
		pResult := Buffer(24)
		if r := this.lib.loads(pJson, pResult) {
			throw Error(
				"Failed to parse JSON (" r ")",
				-1,
				Format(
					"Unexpected character at position {}: '{}'",
					(NumGet(pJson, 'UPtr') - StrPtr(_json)) // 2,
					Chr(NumGet(NumGet(pJson, 'UPtr'), 'Short'))
				)
			)
		}
		result := ComValue(0x400C, pResult.Ptr)[] ; VT_BYREF | VT_VARIANT
		if IsObject(result) {
			ObjRelease(ObjPtr(result))
		}
		return result
	}

	static BoolsAsInts {
		Get => this.lib.bBoolsAsInts
		Set => this.lib.bBoolsAsInts := value
	}

	static EscapeUnicode {
		Get => this.lib.bEscapeUnicode
		Set => this.lib.bEscapeUnicode := value
	}

	static False {
		Get {
			static _ := {value: false, name: 'false'}
			return _
		}
	}

	static fnCastString := Format.Bind('{}')

	static Null {
		Get {
			static _ := {value: '', name: 'null'}
			return _
		}
	}

	static NullsAsStrings {
		Get => this.lib.bNullsAsStrings
		Set => this.lib.bNullsAsStrings := value
	}

	static True {
		Get {
			static _ := {value: true, name: 'true'}
			return _
		}
	}

	static version := "1.6.0-git-dev"

	class MyC {
		static code := Buffer(6960)
		static CodeB64 := (
			"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"
		)

		static __New() {
			if (64 != A_PtrSize * 8) {
				throw Error("$Name does not support " (A_PtrSize * 8) " bit AHK, please run using 64 bit AHK")
			}
			; MCL standalone loader https://github.com/G33kDude/MCLib.ahk
			; Copyright (c) 2023 G33kDude, CloakerSmoker (CC-BY-4.0)
			; https://creativecommons.org/licenses/by/4.0/
			Success := DllCall("Crypt32\CryptStringToBinary",
						"Str", 		this.codeB64,
						"UInt", 	0,
						"UInt", 	1,
						"Ptr", 		buf := Buffer(3980),
						"UInt*", 	buf.Size,
						"Ptr", 		0,
						"Ptr", 		0,
						"UInt"
			)
			if !Success {
				throw Error("Failed to convert MCL b64 to binary")
			}
			r := DllCall("ntdll\RtlDecompressBuffer",
						 "UShort", 	0x102,
						 "Ptr", 	this.code,
						 "UInt", 	6960,
						 "Ptr", 	buf,
						 "UInt", 	buf.Size,
						 "UInt*", 	&DecompressedSize := 0,
						 "UInt"
			)
			if r {
				throw Error("Error calling RtlDecompressBuffer",, Format("0x{:08x}", r))
			}
			for import, offset in Map(['OleAut32', 'SysFreeString'], 5744) {
				if !hDll := DllCall("GetModuleHandle", "Str", import[1], "Ptr") {
					throw Error("Could not load dll " import[1] ": " OsError().Message)
				}
				pFunction := DllCall("GetProcAddress",
									 "Ptr", 	hDll,
									 "AStr", 	import[2],
									 "Ptr"
				)
				if !pFunction {
					throw Error(
						"Could not find function " import[2] " from " import[1] ".dll: "
						OsError().Message
					)
				}
				NumPut("Ptr", pFunction, this.code, offset)
			}
			Success := DllCall("VirtualProtect",
							   "Ptr", 	this.code,
							   "Ptr", 	this.code.Size,
							   "UInt", 	0x40,
							   "UInt*", &old := 0,
							   "UInt"
			)
			if !Success {
				throw Error("Failed to mark MCL memory as executable")
			}
		}

		static dumps(pObjIn, ppszString, pcchString, bPretty, iLevel) {
			return DllCall(this.code.Ptr + 0,
						   "Ptr", 	pObjIn,
						   "Ptr", 	ppszString,
						   "IntP", 	pcchString,
						   "Int", 	bPretty,
						   "Int", 	iLevel,
						   "CDecl Ptr"
			)
		}

		static loads(ppJson, pResult) {
			return DllCall(this.code.Ptr + 3296,
						   "Ptr", ppJson,
						   "Ptr", pResult,
						   "CDecl Int"
			)
		}

		static bBoolsAsInts {
			Get => NumGet(this.code.Ptr + 5344, "Int")
			Set => NumPut("Int", value, this.code.Ptr + 5344)
		}

		static bEscapeUnicode {
			Get => NumGet(this.code.Ptr + 5360, "Int")
			Set => NumPut("Int", value, this.code.Ptr + 5360)
		}

		static bNullsAsStrings {
			Get => NumGet(this.code.Ptr + 5376, "Int")
			Set => NumPut("Int", value, this.code.Ptr + 5376)
		}

		static objFalse {
			Get => NumGet(this.code.Ptr + 5440, "Ptr")
			Set => NumPut("Ptr", value, this.code.Ptr + 5440)
		}

		static objNull {
			Get => NumGet(this.code.Ptr + 5456, "Ptr")
			Set => NumPut("Ptr", value, this.code.Ptr + 5456)
		}

		static objTrue {
			Get => NumGet(this.code.Ptr + 5472, "Ptr")
			Set => NumPut("Ptr", value, this.code.Ptr + 5472)
		}

		static fnGetArray {
			Get => NumGet(this.code.Ptr + 5408, "Ptr")
			Set => NumPut("Ptr", value, this.code.Ptr + 5408)
		}

		static fnGetMap {
			Get => NumGet(this.code.Ptr + 5424, "Ptr")
			Set => NumPut("Ptr", value, this.code.Ptr + 5424)
		}

		static fnCastString {
			Get => NumGet(this.code.Ptr + 5392, "Ptr")
			Set => NumPut("Ptr", value, this.code.Ptr + 5392)
		}
	}
}
