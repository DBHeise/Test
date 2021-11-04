rul ALERT_test 
{
	strings:
		$foo = "barbaz"
	condition:
		all of them
}
rule ALERT_OLE_Embedded_Jar
{
     meta:
         description = "Office document containing OLE embedded java archive"
         author = "Nathan Fowler"
         risk = "high"

     strings:
	 $string1 = { 4f 00 6c 00 65 00 }
	 $string2 = { 01 00 43 00 6f 00 6d 00 70 00 4f 00 62 00 6a 00 }
	 $java1 = ".jar" nocase
	 $java2 = "META-INF/MANIFEST.MF" nocase

     condition:
         all of ($string*) and any of ($java*)
}

rule ALERT_Office_Macro_vba_WinHttpReq
{
     meta:
         description = "Office document containing VBA with Web API calls and .exe"
         author = "Nathan Fowler"
         risk = "high"

     strings:
	 $string1 = { 56 00 42 00 41 00 }
	 $string2 = "://"
	 $string3 = ".exe" nocase
	 $http1 = "WinHttp" nocase
	 $http2 = "URLDownload" nocase
	 $http3 = "urlmon" nocase
	 $http4 = "xmlhttp" nocase
	 $http5 = "internetdownload" nocase
	 $http6 = ".responsebody" nocase
	 $http7 = ".send" nocase

     condition:
         all of ($string*) and any of ($http*)
}

rule ALERT_VBA_SubClassed_IPv4
{
     meta:
         description = "Office document containing an IPv4 address inside the VBA"
         author = "Nathan Fowler"
         risk = "high"

     strings:
         $subclass1 = "ByVal"
	 $subclass2 = "Alias"
	 $subclass3 = "WinHttp" nocase
         $subclass4 = "URLDownload" nocase
         $subclass5 = "urlmon" nocase
         $subclass6 = "xmlhttp" nocase
         $subclass7 = "internetdownload" nocase
	 $subclass8 = ".responsebody" nocase
	 $subclass9 = ".send" nocase
	 $vbe1 = { 56 00 42 00 41 00 }
	 $ip1 = /([0-9]{1,3}\.[0-9]{1,3}\.|\.[0-9]{1,3}\.[0-9]{1,3})/
         $url1 = "://"

     condition:
         any of ($subclass*) and all of ($vbe*) and all of ($ip*) and all of ($url*)
}

rule ALERT_MZ_Header_In_Document
{
	meta:
		description = "MZ Header found in the file"
		author = "Nathan Fowler"
		risk = "high"

	strings:
		$mz1 = { 4D 5A 90 00 03 00 00 00 04 }
		$mz2 = "This program cannot be run in " nocase
	        $mz3 = { D0 CF 11 E0 A1 B1 1A E1 }

	condition:
		all of ($mz*)
}

rule ALERT_Obfuscation_Homerow_Pounders
{
     meta:
        description = "Office document using VBE/VBA with pound-the-keyboard obfuscation on the home row"
        author = "Nathan Fowler"
        risk = "high"

     strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $string1 = "VBE"
        $string2 = "VBA"
	$pound1 = /[asdfghjkl]{8}/

     condition:
	any of ($office*) and any of ($string*) and any of ($pound*)
}

rule ALERT_OLEFormCipher
{
     meta:
        description = "Office document using form data reference AJAX, XML, or Java with Cipher and form submission"
        author = "Nathan Fowler"
        risk = "high"

     strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $string1 = "Content-Disposition: form-data" nocase
        $string2 = "MULTIPART_BOUNDARY" nocase
	$app1 = "AJAX" nocase
	$app2 = "JAVA" nocase
	$app3 = "XML" nocase
	$action1 = "Submit"
	$cipher1 = "Cipher" nocase

     condition:
	any of ($office*) and any of ($string*) and any of ($app*) and all of ($action*) and all of ($cipher*)
}

rule ALERT_rtf_includepicture
{
	meta:
		description = "Detects rtf docs with includepicture, possibly MWI"
		date = "2015-04-30"
		author = "culina@gmail.com"
		risk = "high"

	strings:
		$magic = "{\\rt"
		$string1 = "INCLUDEPICTURE"
		$string2 = "http://"
		$string3 = /\.php\?id=\d/

	condition:
		$magic at 0 and all of ($string*)
}

rule ALERT_OLEHeapSpray
{
     meta:
        description = "Office document usin 0a heap spray with OLE"
        author = "Nathan Fowler"
        risk = "high"

     strings:
        $string1 = "objemb" nocase
        $string2 = "objdata" nocase
        $string3 = "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"

     condition:
        all of them                         
}

rule ALERT_Subclassed_API
{
     meta:
        description = "Office document using obfuscated API subclassing to call DLL libraries using VBA that perform shell or Internet functions"
        author = "Nathan Fowler"
        risk = "high"

     strings:
        $string1 = /Private Declare [^\x20\x09]+ Function/ nocase
        $url1 = "download" nocase
        $url2 = "shell32" nocase
        $url3 = "urlmon" nocase
        $url4 = "inet" nocase
        $url5 = "urlopen" nocase
        $url6 = "createurl" nocase
        $url7 = "internetopen" nocase
        $url8 = "wininet" nocase
        $url9 = "internetget" nocase

     condition:
        all of ($string*) and any of ($url*)
}

rule ALERT_PowerShell
{
     meta:
         description = "Office document using PowerShell to execute a file hidden with bypass policy"
         author = "Nathan Fowler, Phil Fannin, Ryan Moon, Michelle Ticer, Juan Figuera"
         risk = "high"

     strings:
         $string1 = "powershell" nocase
	 $string2 = /[\x22\x27]powershell/ nocase
	 $string3 = /-ExecutionPolicy[\x20\x09]+Bypass/ nocase
	 $string4 = /-WindowStyle[\x20\x09]+hidden/ nocase

     condition:
         all of them
}

rule ALERT_CreateObject_Shell
{
     meta:
         description = "Office document using CreateObject to create a shell object and execute a file"
         author = "Nathan Fowler, Phil Fannin, Ryan Moon, Michelle Ticer, Juan Figuera"
         risk = "medium"

     strings:
         $string1 = /createobject\([\x20\x09]*[\x22\x27][a-z]script\.shell/ nocase
	 $string2 = /\.(exe|vbs|bat|ps[0-9]+)/ nocase
	 $string3 = ".run" nocase

     condition:
         all of them
}

rule ALERT_URL_Concat
{
     meta:
         description = "Office document using string building/concatenation for URLs"
         author = "Nathan Fowler"
         risk = "high"

     strings:
         $string1 = "'ht'+'tp://'" nocase
         $string2 = "'ht' + 'tp://'" nocase

     condition:
         any of them
}

rule ALERT_Office_Macro_vbaweb
{
     meta:
         description = "Office document, zipped, containing VBA with WebSettings.xml"
         author = "Nathan Fowler"
         risk = "high"

     strings:
         $string1 = "/vbaProject" nocase
         $string2 = "/webSettings.xml" nocase
         $string3 = { 50 4b 03 04 14 00 06 00 08 00 00 00 }

     condition:
         all of them
}

rule ALERT_Office_Macro_ActiveMime
{
     meta:
         description = "M$ Office document containing macro with ActiveMime "
         author = "Roberto Martinez"
         risk = "high"

     strings:
         $string1 = "Content-Location: file:///"
         $string2 = "Content-Transfer-Encoding: base64"
         $string3 = "Content-Type: application/x-mso"
         $string4 = "QWN0aXZlTWltZQAA"

     condition:
         all of them
}

rule ALERT_Macro_HTTPCall
{
    meta:
        description = "Office document contains code for HTTP communications"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $http1 = ".open" nocase
        $http2 = ".send" nocase
        $http3 = "HTTP.Status" nocase
        $http4 = "User-Agent" nocase
        $http5 = "Mozilla/"
        $http6 = "200 Then"

    condition:
        any of ($office*) and 3 of ($http*)
}

rule ALERT_Macro_PayloadDownload
{
    meta:
        description = "Office document contains macro code indicating payload download capabilities"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $payload_1 = "URLDownloadToFile"
        $payload_2 = "Msxml2.XMLHTTP"
        $payload_3 = "Microsoft.XMLHTTP"

    condition:
        any of ($office*) and any of ($payload*)
}

rule ALERT_Macro_ExecutesEXE
{
    meta:
        description = "Office document contains code that executes an executable file"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $execute1_1 = /c\:\\/
        $execute1_2 = /\.exe/
        $execute1_3 = "del "

    condition:
        any of ($office*) and all of ($execute*)
}

rule ALERT_Macro_AutoOpen
{
    meta:
        description = "Office document contains auto open code"
        reference = "support.microsoft.com/kb/286310"
        risk = "medium"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $auto1 = "Auto_Open"
        $auto2 = "Auto_Exec"
        $auto3 = "AutoOpen"
        $auto4 = "AutoExec"
        $auto5 = "Workbook_Open"

    condition:
        any of ($office*) and any of ($auto*)
}

rule ALERT_Macro_Obfuscation
{
    meta:
        description = "Office document contains macro obfuscation"
        risk = "medium"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $obfuscation_1 = { 22 20 26 20 }
        $obfuscation_2 = { 20 26 20 22 }
        $obfuscation_3 = { 22 20 2b 20 }
        $obfuscation_4 = { 20 2b 20 22 }
        $obfuscation_5 = "Chr("
        $obfuscation_6 = "HexToString"
        $obfuscation_7 = "CallByName"
        $obfuscation_8 = "StrReverse"
        $obfuscation_9 = "Xor"

    condition:
        any of ($office*) and any of ($obfuscation_*)
}

rule ALERT_Macro_WriteFile
{
    meta:
        description = "Office document contains macro code which writes to a file"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $writefile_1 = "Print #" fullword
        $writefile_2 = "Write" fullword
        $writefile_3 = "Put" fullword
        $writefile_4 = "Output" fullword
        $writefile_5 = "Binary" fullword
        $open1 = "Open" fullword

    condition:
        any of ($office*) and 1 of ($writefile*) and all of ($open*)
}

rule ALERT_Macro_SystemEnvironment
{
    meta:
        description = "Office macro contains code which reads system environment variables"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $environment1 = "Environ" fullword

    condition:
        any of ($office*) and all of ($environment*)
}

rule ALERT_Macro_Shell
{
    meta:
        description = "Office macro contains code to run an executable or system command"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $shell3 = "WScript.Shell"

    condition:
        any of ($office*) and any of ($shell*)
}

rule ALERT_Macro_DeleteFile
{
    meta:
        description = "Office macro contains code to delete a file"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $delete1 = "Kill" fullword

    condition:
        any of ($office*) and any of ($delete*)
}

rule ALERT_Macro_CreateFile
{
    meta:
        description = "Office document macro contains code to create a file"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $create1 = "CreateTextFile"
        $create2 = "ADODB.Stream"
        $create3 = "WriteText"
        $create4 = "SaveToFile"

    condition:
        any of ($office*) and any of ($create*)
}

rule ALERT_ObfuscatedURL
{
    meta:
        description = "Office document contains an obfuscated URL string"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $url1 = "687474703A2F2F"
        $url2 = "Chr(68), Chr(74), Chr(74), Chr(70), Chr(3A), Chr(2F), Chr(2F)"

    condition:
        any of ($office*) and any of ($url*)
}

rule ALERT_Macro_XMLDocument
{
    meta:
        description = "XML document contains an office macro"
        reference = "isc.sans.edu/diary/XML%3A+A+New+Vector+For+An+Old+Trick/19423"
        reference = "www.trustwave.com/Resources/SpiderLabs-Blog/Attackers-concealing-malicious-macros-in-XML-files/?page=1&year=0&month=0"

    strings:

        $xmlmacro1 = "<?xml"
        $xmlmacro2 = "<?mso-application progid=\"Word.Document\"?>"
        $xmlmacro3 = "w:macrosPresent=\"yes\""
      
    condition:
        all of them
}


rule ALERT_Macro_With_HTTP_Call
{
    meta:
        description = "Office document containing XMLHTTP Call"
	author = "Justin Borland"
        risk = "high"

    strings:
        $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
        $office2 = { D0 CF 11 E0 A1 B1 1A E1 }
        $create1 = "XMLHTTP"
	$create2 = "Document_Open"

    condition:
        any of ($office*) and all of ($create*)
}

rule ALERT_Office_Calibri_VBA
{
        meta:
                description = "Office document containing VBA, excessive Calibri declarations, and HTTP Response.Body with OLE Automation"
                author = "Nathan Fowler"
                risk = "high"

        strings:
                $office1 = { D0 CF 11 E0 A1 B1 1A E1 }
                $office2 = { 0143 0061 006c 0069 0062 0072 0069 0031 001e 00dc 0000 0008 0090 0100 0000 02cc c207 0143 0061 006c 0069 0062 0072 0069 0031 001e 00dc 0000 0008 0090 0100 0000 02cc c207 0143 0061 006c 0069 0062 0072 0069 0031 001e 00dc 0000 0008 0090 0100 0000 02cc c207 0143 0061 006c 0069 0062 0072 0069 0031 001e 0068 0101 0038 00bc }

                $vb1 = "VBE"
                $vb2 = "VBA"

                $http1 = "eBody" nocase
                $http2 = "HTTPRequest" nocase
                $http3 = "XMLH" nocase

                $script1 = "Env" nocase
                $script2 = "Script" nocase

                $ole1 = "00020819-0000-0000-C000-000000000046"
                $ole2 = { 7b 00 3000 30 00 30 00 32 00 30 00 38 00 31 00 39 00 2d 00 30 00 30 00 30 00 30 00 2d 00 30 00 30 00 30 00 30 00 2d 00 43 00 30 00 30 00 30 00 2d 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 34 00 36 00 7d }

               
        condition:
                all of ($office*) and any of ($vb*) and any of ($http*) and any of ($ole*) and any of ($script*)
}

rule ALERT_Access_Hidden_Tables_HTTP
{
        meta:
                description = "Office document containing VBA, Access linked databases, and HTTP Requests with OLE automation"
                author = "Nathan Fowler"
                risk = "high"

        strings:
                $office1 = { D0 CF 11 E0 A1 B1 1A E1 }

                $vb1 = "VBE"
                $vb2 = "VBA"

                $http1 = "HTTPRequest" nocase
                $http2 = "XMLH" nocase
                $http3 = "ResponseBody" nocase

                $ole1 = "OLE"
                $ole2 = { 23 00 4f 00 4c 00 45 00 }
                $ole3 = { 73 00 74 00 64 00 6f 00 6c 00 65 00 }

                $access1 = "LinkedDatabase" nocase
                $access2 = "MSysObject" nocase
                $access3 = "DATABASE=" nocase

        condition:
                all of ($office*) and any of ($vb*) and any of ($http*) and any of ($ole*) and any of ($access*)
}

rule ALERT_Word2007_Interop_Assy_Excessive_Space
{
        meta:
                description = "Office document containing Word 2007 Interop Assemblies, excessive space (heap spray?), and VBA"
                author = "Nathan Fowler"
                risk = "high"

        strings:
                $office1 = { D0 CF 11 E0 A1 B1 1A E1 }

                $string1 = "00020905-0000-0000-C000-000000000046"
                $string2 = { 7b 00 30 00 30 00 30 00 32 00 30 00 39 00 30 00 35 00 2d 00 30 00 30 00 30 00 30 00 2d 00 30 00 30 00 30 00 30 00 2d 00 43 00 30 00 30 00 30 00 2d 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 30 00 34 00 36 00 7d }

                $vb1 = "VBE"
                $vb2 = "VBA"

                $subclass1 = "ByVal" nocase
                $subclass2 = "Private Declare Function" nocase
                $subclass3 = "Alias " nocase
                $subclass4 = " Alias" nocase

                $bad1 = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 }

        condition:
                any of ($office*) and any of ($string*) and any of ($vb*) and any of ($bad*) and any of ($subclass*)
}

rule ALERT_cf_embedded_exe
{
        meta:
                maltype = "all"
                filetype = "any"
                yaraexchange = "public content"
        strings:
                $a = "DOS mode" nocase
                $b = { 44 4F 53 20 6D 6F 64 65 }
        condition:
        $a or $b
}

rule ALERT_cf_exe_dropper_sfx
{
        meta:
                author = "Blake Darche"
                maltype = "all"
                filetype = "exe"
                yaraexchange = "No distribution without author's consent"
                version = "0.1"
                description = "detects dropper sfx"
                date = "2012-10"
        strings:
                $a = ";The comment below contains SFX script commands"
                $b = "Setup=" ascii wide
                $c = "Silent=1" ascii wide
                $PDB = "WinRAR" ascii wide
        condition:
                uint16(0) == 0x5A4D and all of them
}

rule ALERT_cf_hlp_malicious_help_file
{
        meta:
                author = "Jaime Blasco"
                maltype = "all"
                filetype = "hlp"
                yaraexchange = "No distribution without author's consent"
                version = "0.1"
                description = "Suspicious help file"
                sample = "https://www.virustotal.com/file/9b293320d1128ada81b528cff1a1ea38dfa67e068f5a922d2d788891f3275dc4/analysis/"
                date = "2012-09"
        strings:
                $type0 = {4C 4E 02 00}
                $type1 = {3F 5F 03 00}
                $patt1 = /RR\(.KERNEL32.DLL.,/ nocase
                $patt3 = "CreateThread" nocase
        condition:
                $type0 at 0 or $type1 at 0 and $patt1 and $patt3
}
rule ALERT_cf_java_allatori_obfuscator
{
  meta:
    description = "detects the Allatori Obfuscator for Jar files"
    author = "sconzo@visiblerisk.com"
    yaraexchange = "No distribution without author's consent"
		filetype = "jar"
		date = "2013-02"
  strings:
    $pk = "PK"
    $1 = "Obfuscation by Allatori Obfuscator"
    $2 = "http://www.allatori.com"
  condition:
    $pk at 0 and ($1 and $2)
}

rule ALERT_cf_java_network_connectivity
{
meta:
		author = "Glenn Edwards (@hiddenillusion)"
		maltype = "all"
		filetype = "jar"
		yaraexchange = "No distribution without author's consent"
		version = "0.1"
		ref = "http://docs.oracle.com"
		date = "2012-09"
	strings:
		$magic = { CA FE BA BE }
		/* Network indicators */
		$conn0 = "ServerSocket"
		$conn1 = "lport"
		$conn2 = "host"
		$conn3 = /socket(lhost, lport)/
		$network0 = "getMbeanServer" //used with MarshallObject
		$network1 = "URLConnection" //URL class can also be used to access files in the local file system
		$network2 = /get(Input|Output)Stream/
		$network3 = "openConnection"
	condition:
		$magic at 0 and 3 of ($conn*) and 1 of ($network*)
}

rule ALERT_cf_java_cve_2012_4681
{
	meta:
	author = "Jaime Blasco"
	maltype = "all"
	filetype = "jar"
	yaraexchange = "No distribution without author's consent"                 
	source = "alienvault"
	date = "2012-08"
	weight=100
	strings:
	$a =  "java/security/ProtectionDomain"
	$b = "java/security/Permissions"
	$c = "java/security/cert/Certificate"
	$d = "setSecurityManager"
	$e = "file:///"
	$f = "sun.awt.SunToolkit"
	$g = "getField"
	condition:
	all of them
}

rule ALERT_cf_java_execute_write
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://docs.oracle.com"
		maltype = "all"
		filetype = "jar"
		yaraexchange = "No distribution without author's consent"
		date = "2012-09"
	strings:
		$magic = { CA FE BA BE }
		/* Local execution */
		$exec0 = "Runtime.getRuntime"
		$exec1 = "exec"
		/* Exploit */
		$exp0 = /arrayOf(Byte|String)/
		$exp1 = "toByteArray"
		$exp2 = "HexDecode"
		$exp3 = "StringtoBytes"
		$exp6 = "InputStream"
		$exp7 = "Exception.printStackTrace"
		$fwrite0 = "FileOutputStream" /*contains a byte stream with the serialized representation of an object given to its constructor*/
		$fwrite3 = "MarshalledObject"
		$fwrite4 = "writeObject"
		$fwrite5 = "OutputStreamWriter"
		/* Loader indicators */
		$load0 = "getResourceAsStream"
		$load1 = /l(port|host)/
		$load2 = "ObjectInputStream"
		$load3 = "ArrayOfByte"
				//$gen1 = "file://"
	condition:
		$magic at 0 and ((all of ($exec*) and 2 of ($fwrite*)) or (2 of ($exp*) and 2 of ($load*)))
}

rule ALERT_cf_java_changing_security
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://docs.oracle.com"
		maltype = "all"
		filetype = "jar"
		yaraexchange = "No distribution without author's consent"
		date = "2012-09"
	strings:
		$magic = { CA FE BA BE }
		/* Modifying local security : a class that allows applications to implement a security policy */
		$manager = /[sg]etSecurityManager/
		$sec0 = "PrivilegedActionException"
		$sec1 = "AccessController.doPrivileged"
		$sec2 = "AllPermission"
		$sec3 = "ProtectionDomain"
		$gen1 = "file://"
	condition:
		$magic at 0 and $manager and 2 of ($sec*) and $gen1
}

rule ALERT_cf_jar_cve_2013_0422
{
        meta:
                description = "Java Applet JMX Remote Code Execution"
                cve = "CVE-2013-0422"
                ref = "http://pastebin.com/JVedyrCe"
                author = "adnan.shukor@gmail.com"
                date = "12-Jan-2013"
                version = "1"
                impact = 4
                hide = false
        strings:
                $0422_1 = "com/sun/jmx/mbeanserver/JmxMBeanServer" fullword
                $0422_2 = "com/sun/jmx/mbeanserver/JmxMBeanServerBuilder" fullword
                $0422_3 = "com/sun/jmx/mbeanserver/MBeanInstantiator" fullword
                $0422_4 = "findClass" fullword
                $0422_5 = "publicLookup" fullword
                $class = /sun\.org\.mozilla\.javascript\.internal\.(Context|GeneratedClassLoader)/ fullword 
        condition:
                (all of ($0422_*)) or (all of them)
}

rule ALERT_cf_java_malicious_jar
{
    meta:
         author = "Mike Remen"
        description = "Class files found within malicious jar files"
        yaraexchange = "No distribution without author's consent"
        filetype = "jar"
        date = "2013-03"
    strings:
        $magic = { 50 4B 03 04 }
        $class_name1 = "web.class"
        $class_name2 = "stream.class"
        $class_name3 = "Asd.class"
        $class_name4 = "CXkpO/McOhGk.class"
        $class_name5 = "van.class"
        $class_name6 = "CXkpO/cPbVu.class"
        $class_name7 = "pou.class"
        $class_name8 = "CXkpO/dsjDBzBWd.class"
        $class_name9 = "hw.class"
        $class_name10 = "mac.class"
        $class_name11 = "test.class"
        $class_name12 = "go.class"
        $class_name13 = "PlayStart.class"
        $class_name14 = "Dosth.class"
        $class_name15 = "Veros.class"
        $class_name16 = "codehex.class"
        $class_name17 = "Impossible.class"
        $class_name18 = "RunnerGood.class"
        $class_name19 = "popers.class"
        $class_name20 = /\W[a-z]{1}\.class/
        $class_name21 = "test2.class"
        $class_name22 = "BurkinoGoso.class"
        $class_name23 = "CXkpO/iOeOOv.class"
        $class_name24 = "vcs.class"
        $class_name25 = "HOcTub.class"
        $class_name26 = "HUevxo.class"
        $class_name27 = "MjIxEfW.class"
        $class_name28 = "MYLzX.class"
        $class_name29 = "RhaTlCpo.class"
        $class_name30 = "TOe.class"
        $class_name31 = "waIcSy.class"
        $class_name32 = "YeIUXV.class"
        $class_name33 = "yXPqkrkzi.class"
        $class_name34 = "AxQwsAx.class"
        $class_name35 = "FuNWTkWNK.class"
        $class_name36 = "hAfBhfMU.class"
        $class_name37 = "CXkpO/xfANSZO.class"
        $class_name38= "CXkpO/zaDtyHdO.class"
        $class_name39= "SunInit.class"
        $class_name40= "MyApplet.class"
        $class_name41 = "NanoMaterial.class"    
        $class_name42 = "Next.class"
        $class_name43 = "PackageLoader.class"
        $class_name44 = "axe.class"
        $class_name45 = "ewbtergzfa.class"
        $class_name46 = "ewbtergzfb.class"
        $class_name47 = "ewbtergzfc.class"
        $class_name48 = "ors.class"
        $class_name49 = "sofosfuckoffmanyuoshit.class"
        $class_name50 = "stringOfLife.class"
        $class_name51 = "test3.class"
        $class_name52 = "tt.class"
        $class_name53 = "xbb.class"
        $class_name54 = "payload.class"
        $class_name55 = "ImAlpha.class"

    condition:
                $magic at 0 and 2 of ($class*)
}

rule ALERT_cf_java_possible_exploit
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		maltype = "all"
		filetype = "jar"
		yaraexchange = "No distribution without author's consent"
		version = "0.1"
		ref = "http://docs.oracle.com"
		source = "Yara Exchange"
		date = "2012-09"
	strings:
		$magic = { CA FE BA BE }
		$exp0 = "arrayOfByte"
		$exp1 = "Character.digit"
		$exp2 = "ByteArrayInputStream"
		$exp3 = "StringBuilder"
		$exp4 = "printStackTrace"
		$exp5 = "String.charAt"
		$perm0 = "ProtectionDomain"
		$perm1 = "localPermissions"
	condition:
		$magic at 0 and all of ($perm*) and 1 of ($exp*)
}

rule ALERT_cf_java_cve_2010_0887_jdt
{
	meta:
		cve = "CVE-2010-0887"
		ref = "http://blog.xanda.org/2010/04/21/yara-rule-for-cve-2010-0886-cve-2010-0887"
		impact = 7
		maltype = "all"
		filetype = "jar"
		yaraexchange = "Public content blog.xanda.org"
	strings:
		$cve20100887_1 = "CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA" nocase fullword
		$cve20100887_2 = "document.createElement(\"OBJECT\")" nocase fullword
		$cve20100887_3 = "application/npruntime-scriptable-plugin;deploymenttoolkit" nocase fullword
		$cve20100887_4 = "application/java-deployment-toolkit" nocase fullword
		$cve20100887_5 = "document.body.appendChild(" nocase fullword
		/*$cve20100887_6 = /.*?.launch\(.*?\)/$cve20100887_7 = "-J-jar -J" nocase fullword*/ //slow regex
	condition:
	3 of them
}

rule ALERT_cf_java_system_cmds
{
meta:
		author = "Glenn Edwards (@hiddenillusion)"
		maltype = "all"
		filetype = "jar"
		yaraexchange = "No distribution without author's consent"
		version = "0.1"
		ref = "http://docs.oracle.com"
		date = "2012-09"
	strings:
		$magic = { CA FE BA BE }
		/* System commands */
		$cmd0 = "cmd.exe"
		$cmd1 = "/bin/sh"
		$cmd2 = "chmod"
		/* Payload */
		$fingerprint1 = /get(Property|env)/
		$fingerprint2 = /(os.name|java.io.tmpdir)/
		$fingerprint3 = "Math.random"
		$fingerprint4 = "indexOf" //usually used to get result of $fingerprint2
	condition:
		$magic at 0 and (2 of ($cmd*) or (1 of ($cmd*) and 3 of ($fingerprint*)))
}


//This will work on the non docx ones, or if you extract the docx:

rule ALERT_cf_flash_cve_2012_5054_dev
{
    meta:
        author = "@vicheck"
        source = "Yara Exchange"
        date = "2013/02/13"
        comment = "CVE-2012-5054"
        version = "1.0"

    strings:
        $matrix3d = {77 72 69 74 65 44 6F 75 62 6C 65 08 4D 61 74 72 69 78 33 44 06 4F 62 6A 65 63 74 0B 66 6C 61 73 68 2E 6D 65 64 69 61 05 53 6F 75 6E 64 0C 66 6C 61 73 68 2E 73 79 73 74 65 6D 0C 43 61 70 61 62 69 6C 69 74 69 65 73 07 76 65 72 73 69 6F 6E 0B 74 6F 4C 6F 77 65 72 43 61 73 65 10  77 69 6E}

    condition:
        $matrix3d

}

rule ALERT_cf_flash_cve_2014_1776_dev
{
	meta: 
		description = "Flash exploit used in recent IE zero-day vulnerability (CVE-2014-1776)."
		reference = "http://www.fireeye.com/blog/uncategorized/2014/04/new-zero-day-exploit-targeting-internet-explorer-versions-9-through-11-identified-in-targeted-attacks.html"
		author = "Chris Malvitz"
		yaraexchange = "No distribution without author's consent"
		date = "2014-05"
		filetype = "swf"
		md5 = "746e6437fb8fdf5f863214c5ef5d1efc, 44439b7924eec5bf28634065d12ab12e"
	strings:
		$s1 = "Pidj7gbU"
		$s2 = "can't search the module base!"
		$s3 = "630ed5495eaad7cd8b52d42b60f0757f103583276a31f7cbee2201fd80f167"
		$s4 = "cb5fb86dbbafd70ad04504"
		$s5 = "ZwProtectVirtualMemory"
		$s6 = "SetThreadContext"
		$s7 = "KERNEL32" nocase
	condition:
		all of them
}

