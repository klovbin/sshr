# sshr ext import winscp [file.ini...] reads the saved sites of WinSCP and
# prints the SSH ones as {"hosts": [...]} for sshr
#
# WinSCP keeps its configuration in the registry, HKCU\Software\Martin
# Prikryl\WinSCP 2\Sessions, one key per site, or in WinSCP.ini, next to
# WinSCP.exe for the portable version or in %APPDATA%, the sites sit in
# [Sessions\name] sections there, the files given as arguments are read
# instead, the names and the string values are escaped the way PuTTY
# escapes them (%XX), a value that starts with an escaped UTF-8 BOM is
# UTF-8, else the ANSI code page, a / in a name is a folder, it becomes
# tags, the keys and their meaning come from source/core/SessionData.cpp
# and HierarchicalStorage.cpp of WinSCP
#
# FSProtocol 0 (SCP), 1 (SFTP, the default) and 2 (SFTP only) are SSH, FTP,
# WebDAV and S3 sites are left out, a tunnel becomes a jump host, the
# passwords (Password, TunnelPasswordPlain, ProxyPassword) are never read,
# a .ppk key is left out with a note, OpenSSH cannot read it
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Files)

$ErrorActionPreference = 'Stop'
# UTF-8 writers on the standard streams, setting [Console]::OutputEncoding
# throws without a console on PowerShell 5.1 and changes the user's console
$utf8 = New-Object System.Text.UTF8Encoding($false)
$stdout = New-Object System.IO.StreamWriter([Console]::OpenStandardOutput(), $utf8)
$stderr = New-Object System.IO.StreamWriter([Console]::OpenStandardError(), $utf8)
$stderr.AutoFlush = $true

if ($env:SSHR_EXT_PROTOCOL -ne '1') {
	$stderr.WriteLine('winscp: run me with sshr ext import winscp, not by hand')
	exit 2
}

$registryKey = 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'

# Clean drops control characters, DEL and the C1 controls, a site may
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

function OkPort($p) {
	$n = 0
	"$p" -match '^[0-9]+$' -and [int]::TryParse("$p", [ref]$n) -and $n -ge 1 -and $n -le 65535
}

# Ansi is the ANSI code page of the system, the one WinSCP falls back to
function Ansi {
	try {
		[System.Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage)
	} catch {
		[System.Text.Encoding]::GetEncoding(1252)
	}
}

# Unmunge reverses the escaping of WinSCP: %XX is a byte, the bytes are
# UTF-8 after an escaped BOM, else the ANSI code page
function Unmunge([string]$s) {
	$bytes = New-Object System.Collections.Generic.List[byte]
	for ($i = 0; $i -lt $s.Length; $i++) {
		$c = $s[$i]
		if ($c -eq '%' -and $i + 2 -lt $s.Length -and $s.Substring($i + 1, 2) -match '^[0-9A-Fa-f]{2}$') {
			$bytes.Add([Convert]::ToByte($s.Substring($i + 1, 2), 16))
			$i += 2
		} elseif ([int]$c -lt 128) {
			$bytes.Add([byte][int]$c)
		} else {
			# WinSCP writes ASCII only, a hand edited value keeps its text
			foreach ($b in [System.Text.Encoding]::UTF8.GetBytes([string]$c)) { $bytes.Add($b) }
		}
	}
	$a = $bytes.ToArray()
	if ($a.Length -ge 3 -and $a[0] -eq 0xEF -and $a[1] -eq 0xBB -and $a[2] -eq 0xBF) {
		return [System.Text.Encoding]::UTF8.GetString($a, 3, $a.Length - 3)
	}
	(Ansi).GetString($a)
}

# ReadText decodes an INI file: UTF-16 by its BOM, UTF-8 when it decodes,
# else the ANSI code page
function ReadText([string]$path) {
	$b = [System.IO.File]::ReadAllBytes($path)
	if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) {
		return [System.Text.Encoding]::Unicode.GetString($b, 2, $b.Length - 2)
	}
	$skip = 0
	if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $skip = 3 }
	try {
		return (New-Object System.Text.UTF8Encoding($false, $true)).GetString($b, $skip, $b.Length - $skip)
	} catch {
	}
	(Ansi).GetString($b)
}

# On tells a boolean of WinSCP: on and off in an INI file, a number in
# the registry and in older files
function On([string]$s) {
	$s = $s.Trim().ToLower()
	$s -eq 'on' -or ($s -match '^-?[0-9]+$' -and [long]$s -ne 0)
}

# SplitUser splits user@host the way WinSCP does, a user in the host field
# wins over the user field
function SplitUser([string]$hostName, [string]$user) {
	$at = $hostName.LastIndexOf('@')
	if ($at -ge 0) { return @($hostName.Substring($at + 1), $hostName.Substring(0, $at)) }
	@($hostName, $user)
}

# sites maps the name as stored (escaped) to its raw values, compared by
# case as sshr compares keys, a PowerShell hashtable ignores case
$sites = New-Object 'System.Collections.Generic.Dictionary[string,hashtable]' ([StringComparer]::Ordinal)
$order = New-Object System.Collections.Generic.List[string]

function AddSite([string]$name, [hashtable]$values) {
	if (-not $sites.ContainsKey($name)) { $order.Add($name) }
	$sites[$name] = $values
}

if (-not $Files) {
	$ini = if ($env:APPDATA) { Join-Path $env:APPDATA 'WinSCP.ini' } else { '' }
	if ($ini -ne '' -and (Test-Path -LiteralPath $ini -PathType Leaf)) {
		$Files = @($ini)
	} elseif (Test-Path $registryKey) {
		foreach ($key in Get-ChildItem $registryKey) {
			# the values come from the key itself, Get-ItemProperty mixes in
			# PSPath and the like and expands %VARS%
			$values = @{}
			foreach ($n in $key.GetValueNames()) {
				$values[$n] = [string]$key.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
			}
			AddSite $key.PSChildName $values
		}
	} else {
		$stderr.WriteLine('winscp: no sites in the registry and no WinSCP.ini in %APPDATA%, for the portable version pass the WinSCP.ini next to WinSCP.exe')
	}
}

foreach ($f in $Files) {
	if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
		$stderr.WriteLine("winscp: $(Clean $f) is not a file")
		exit 1
	}
	$item = Get-Item -LiteralPath $f
	# a link in a synced folder can point at any file
	if ($item.LinkType) {
		$stderr.WriteLine("winscp: $(Clean $f) is a link, it is skipped")
		continue
	}
	if ($item.Length -gt 4MB) {
		$stderr.WriteLine("winscp: $(Clean $f) is over 4 MiB, it is skipped")
		continue
	}
	$cur = $null
	foreach ($line in (ReadText $f) -split "`r?`n") {
		if ($line -match '^\[Sessions\\(.+)\]$') {
			$cur = $Matches[1]
			AddSite $cur @{}
		} elseif ($line -match '^\[') {
			$cur = $null
		} elseif ($cur -and $line -match '^([^=]+)=(.*)$') {
			$sites[$cur][$Matches[1]] = $Matches[2]
		}
	}
}

# WinSCP loads a site over a copy of Default Settings and saves only the
# values that differ from it, a site without FSProtocol has the protocol
# of Default Settings
$defaults = if ($sites.ContainsKey('Default%20Settings')) { $sites['Default%20Settings'] } else { @{} }

$hosts = New-Object System.Collections.ArrayList
foreach ($name in $order) {
	if ($name -eq 'Default%20Settings') { continue }
	$v = @{}
	foreach ($k in $defaults.Keys) { $v[$k] = $defaults[$k] }
	foreach ($k in $sites[$name].Keys) { $v[$k] = $sites[$name][$k] }
	# a saved workspace and a session hidden with the _!_ prefix are no
	# sites, WinSCP shows neither in its list
	if ((On "$($sites[$name]['IsWorkspace'])") -or (Unmunge $name).StartsWith('_!_')) { continue }
	$proto = "$($v['FSProtocol'])".Trim()
	if ($proto -ne '' -and $proto -ne '0' -and $proto -ne '1' -and $proto -ne '2') { continue }
	$label = Clean (Unmunge $name)
	$split = SplitUser (Clean (Unmunge "$($v['HostName'])")) (Clean (Unmunge "$($v['UserName'])"))
	$hostName = $split[0]
	$user = $split[1]
	if ($hostName -eq '' -or $label -eq '') { continue }
	# the name as stored is the key, the folder is part of it
	$h = [ordered]@{ key = (Clean $name); name = $label; host = $hostName }
	$parts = @($label -split '/')
	if ($parts.Count -gt 1 -and $parts[-1] -ne '') {
		$h.name = $parts[-1]
	}
	if (OkPort $v['PortNumber']) { $h.port = [int]$v['PortNumber'] }
	if ($user -ne '') { $h.user = $user }
	$keyFile = Clean (Unmunge "$($v['PublicKeyFile'])")
	if ($keyFile -match '\.ppk$') {
		$stderr.WriteLine("winscp: ${label}: the key $keyFile is a PuTTY key, convert it with puttygen key.ppk -O private-openssh -o key and set it in sshr")
	} elseif ($keyFile -ne '') {
		$h.key_file = $keyFile
	}
	if (On "$($v['Tunnel'])") {
		$t = SplitUser (Clean (Unmunge "$($v['TunnelHostName'])")) (Clean (Unmunge "$($v['TunnelUserName'])"))
		if ($t[0] -ne '') {
			$jump = $t[0]
			if ($t[1] -ne '') { $jump = $t[1] + '@' + $jump }
			if ((OkPort $v['TunnelPortNumber']) -and [int]$v['TunnelPortNumber'] -ne 22) { $jump = $jump + ':' + [int]$v['TunnelPortNumber'] }
			$h.jump = $jump
		}
	}
	$proxy = Clean "$($v['ProxyMethod'])"
	if ($proxy -ne '' -and $proxy -ne '0' -and $proxy -ne 'None') {
		$stderr.WriteLine("winscp: ${label}: its proxy (ProxyMethod $proxy) is not carried, sshr goes direct or through jump hosts")
	}
	if ($parts.Count -gt 1) {
		$tags = @($parts[0..($parts.Count - 2)] | Where-Object { $_ -ne '' })
		if ($tags.Count -gt 0) { $h.tags = $tags }
	}
	[void]$hosts.Add($h)
}

$stdout.WriteLine((ConvertTo-Json -InputObject ([ordered]@{ hosts = $hosts }) -Depth 4 -Compress))
$stdout.Flush()
