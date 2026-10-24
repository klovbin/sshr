# sshr ext import putty [file.reg...] reads the saved sessions of PuTTY on
# Windows and prints them as {"hosts": [...]} for sshr
#
# PuTTY keeps its sessions in the registry, HKCU\Software\SimonTatham\
# PuTTY\Sessions, one key per session, its name is the session name with
# %XX escapes, a file exported with reg export or regedit is read instead
# when one is given, PuTTY saves no password, OpenSSH cannot read a .ppk
# key, so it is left out with a note, an SSH proxy (ProxyMethod 6) becomes
# a jump host, other proxies are not carried, the rules are the ones of
# putty.sh, so a session gives the same host on every system
# every argument is a file, without ValueFromRemainingArguments only the
# first one is bound
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Files)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

if ($env:SSHR_EXT_PROTOCOL -ne '1') {
	[Console]::Error.WriteLine('putty: run me with sshr ext import putty, not by hand')
	exit 2
}

$sessionsKey = 'Software\SimonTatham\PuTTY\Sessions'

# Clean drops control characters, DEL and the C1 controls, a session may
# carry any of them and they would drive the terminal or break the JSON
function Clean([string]$s) {
	$out = New-Object System.Text.StringBuilder
	foreach ($c in $s.ToCharArray()) {
		$n = [int]$c
		if ($n -lt 32 -or ($n -ge 127 -and $n -le 159)) { continue }
		[void]$out.Append($c)
	}
	$out.ToString()
}

# Unescape decodes the %XX escapes PuTTY writes into a session name as
# UTF-8, a name that does not decode stays as it is
function Unescape([string]$s) {
	$bytes = New-Object System.Collections.Generic.List[byte]
	for ($i = 0; $i -lt $s.Length; $i++) {
		$c = $s[$i]
		if ($c -eq '%' -and $i + 2 -lt $s.Length -and $s.Substring($i + 1, 2) -match '^[0-9A-Fa-f]{2}$') {
			$bytes.Add([Convert]::ToByte($s.Substring($i + 1, 2), 16))
			$i += 2
		} else {
			foreach ($b in [System.Text.Encoding]::UTF8.GetBytes([string]$c)) { $bytes.Add($b) }
		}
	}
	try {
		(New-Object System.Text.UTF8Encoding($false, $true)).GetString($bytes.ToArray())
	} catch {
		$s
	}
}

# ReadReg decodes a .reg file: regedit and reg export write UTF-16 with a
# BOM, a file without a BOM is UTF-8 when it decodes as UTF-8, else
# Windows-1252 (REGEDIT4), Get-Content of PowerShell 5.1 would read a
# UTF-8 file without a BOM as ANSI
function ReadReg([string]$path) {
	$b = [System.IO.File]::ReadAllBytes($path)
	if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) {
		return [System.Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2)
	}
	if ($b.Length -ge 2 -and $b[0] -eq 0xFE -and $b[1] -eq 0xFF) {
		return [System.Text.Encoding]::BigEndianUnicode.GetString($b, 2, $b.Length - 2)
	}
	$skip = 0
	if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $skip = 3 }
	try {
		(New-Object System.Text.UTF8Encoding($false, $true)).GetString($b, $skip, $b.Length - $skip)
	} catch {
		[System.Text.Encoding]::GetEncoding(1252).GetString($b)
	}
}

function OkPort($p) {
	$n = 0
	"$p" -match '^[0-9]+$' -and [int]::TryParse("$p", [ref]$n) -and $n -ge 1 -and $n -le 65535
}

# sessions maps the session name as stored (escaped) to its values
$sessions = [ordered]@{}

if ($Files) {
	foreach ($f in $Files) {
		if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
			[Console]::Error.WriteLine("putty: $(Clean $f) is not a file")
			exit 1
		}
		if ((Get-Item -LiteralPath $f).Length -gt 4MB) {
			[Console]::Error.WriteLine("putty: $(Clean $f) is over 4 MiB, it is skipped")
			continue
		}
		$cur = $null
		foreach ($line in (ReadReg $f) -split "`r?`n") {
			if ($line -match '^\[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\(.+)\]$') {
				$cur = $Matches[1]
				$sessions[$cur] = @{}
			} elseif ($line -match '^\[') {
				$cur = $null
			} elseif ($cur -and $line -match '^"((?:[^"\\]|\\.)*)"="((?:[^"\\]|\\.)*)"$') {
				$sessions[$cur][$Matches[1]] = ($Matches[2] -replace '\\(.)', '$1')
			} elseif ($cur -and $line -match '^"((?:[^"\\]|\\.)*)"=dword:([0-9A-Fa-f]{8})$') {
				$sessions[$cur][$Matches[1]] = [string][Convert]::ToInt32($Matches[2], 16)
			}
		}
	}
} else {
	$root = "HKCU:\$sessionsKey"
	if (Test-Path $root) {
		foreach ($key in Get-ChildItem $root) {
			$values = @{}
			$props = Get-ItemProperty -LiteralPath $key.PSPath
			foreach ($p in $props.PSObject.Properties) {
				if ($p.Name -notlike 'PS*') { $values[$p.Name] = [string]$p.Value }
			}
			$sessions[$key.PSChildName] = $values
		}
	}
}

$hosts = New-Object System.Collections.ArrayList
foreach ($name in $sessions.Keys) {
	if ($name -eq 'Default%20Settings') { continue }
	$v = $sessions[$name]
	$proto = "$($v['Protocol'])".ToLower()
	if ($proto -ne '' -and $proto -ne 'ssh' -and $proto -ne 'default') { continue }
	$hostName = Clean "$($v['HostName'])"
	$user = Clean "$($v['UserName'])"
	if ($hostName -eq '') { continue }
	$at = $hostName.IndexOf('@')
	if ($at -ge 0) {
		if ($user -eq '') { $user = $hostName.Substring(0, $at) }
		$hostName = $hostName.Substring($at + 1)
	}
	# the name as stored is the key, two names that decode the same stay two
	$h = [ordered]@{ key = (Clean $name); name = (Clean (Unescape $name)); host = $hostName }
	if (OkPort $v['PortNumber']) { $h.port = [int]$v['PortNumber'] }
	if ($user -ne '') { $h.user = $user }
	$keyFile = Clean "$($v['PublicKeyFile'])"
	if ($keyFile -match '\.ppk$') {
		[Console]::Error.WriteLine("putty: $($h.name): the key $keyFile is a PuTTY key, convert it with puttygen key.ppk -O private-openssh -o key and set it in sshr")
	} elseif ($keyFile -ne '') {
		$h.key_file = $keyFile
	}
	if ("$($v['ProxyMethod'])" -eq '6' -and "$($v['ProxyHost'])" -ne '') {
		$jump = Clean "$($v['ProxyHost'])"
		if ("$($v['ProxyUsername'])" -ne '') { $jump = (Clean "$($v['ProxyUsername'])") + '@' + $jump }
		if ((OkPort $v['ProxyPort']) -and [int]$v['ProxyPort'] -ne 22) { $jump = $jump + ':' + [int]$v['ProxyPort'] }
		$h.jump = $jump
	} elseif ("$($v['ProxyMethod'])" -ne '' -and "$($v['ProxyMethod'])" -ne '0') {
		[Console]::Error.WriteLine("putty: $($h.name): its proxy (ProxyMethod $(Clean "$($v['ProxyMethod'])")) is not carried, sshr goes direct or through jump hosts")
	}
	[void]$hosts.Add($h)
}

ConvertTo-Json -InputObject ([ordered]@{ hosts = $hosts }) -Depth 4 -Compress
