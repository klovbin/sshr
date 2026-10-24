# sshr ext import mobaxterm [file...] reads the SSH sessions of MobaXterm
# and prints them as {"hosts": [...]} for sshr
#
# MobaXterm keeps its sessions in MobaXterm.ini, in %APPDATA%\MobaXterm
# for the installed edition, next to MobaXterm.exe for the portable one,
# the files given as arguments are read instead: MobaXterm.ini, an export
# (.mxtsessions) or one session (.moba), the sessions sit in [Bookmarks]
# and [Bookmarks_N] sections, SubRep is the folder, it becomes tags, a
# session is a line "name=flag#icon#fields#...", the fields of the first
# group are split by %, for SSH (type 0) 1 is the host, 2 the port, 3 the
# user, 8, 9 and 10 the SSH gateways split by __PIPE__, 14 the private
# key, 19 the proxy type, the layout is the one described for MobaXterm
# 26.3 in gist.github.com/Ruzgfpegk/ab597838e4abbe8de30d7224afd062ea,
# older versions write fewer fields with the same first ones
#
# No password is read, MobaXterm keeps them in its own encrypted store,
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
	$stderr.WriteLine('mobaxterm: run me with sshr ext import mobaxterm, not by hand')
	exit 2
}

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

function OkPort($p) {
	$n = 0
	"$p" -match '^[0-9]+$' -and [int]::TryParse("$p", [ref]$n) -and $n -ge 1 -and $n -le 65535
}

# ReadText decodes a file: UTF-8 with or without a BOM when it decodes as
# UTF-8, else Windows-1252, the charset MobaXterm writes
function ReadText([string]$path) {
	$b = [System.IO.File]::ReadAllBytes($path)
	$skip = 0
	if ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF) { $skip = 3 }
	try {
		(New-Object System.Text.UTF8Encoding($false, $true)).GetString($b, $skip, $b.Length - $skip)
	} catch {
		[System.Text.Encoding]::GetEncoding(1252).GetString($b)
	}
}

# KeyPath turns the drive placeholder MobaXterm writes into the path
function KeyPath([string]$s) {
	(Clean $s) -replace '_CurrentDrive_', 'C'
}

# Jumps builds the jump hosts of the gateway lists, user@host:port each,
# joined by commas as ssh -J takes them
function Jumps([string]$hosts, [string]$ports, [string]$users) {
	$hs = $hosts -split '__PIPE__'
	$ps = $ports -split '__PIPE__'
	$us = $users -split '__PIPE__'
	$out = @()
	for ($i = 0; $i -lt $hs.Count; $i++) {
		$j = Clean $hs[$i]
		if ($j -eq '') { continue }
		$u = if ($i -lt $us.Count) { (Clean $us[$i]) } else { '' }
		if ($u -ne '') { $j = $u + '@' + $j }
		if ($i -lt $ps.Count -and (OkPort $ps[$i]) -and [int]$ps[$i] -ne 22) { $j = $j + ':' + [int]$ps[$i] }
		$out += $j
	}
	$out -join ','
}

if (-not $Files) {
	$places = @()
	if ($env:APPDATA) { $places += Join-Path $env:APPDATA 'MobaXterm\MobaXterm.ini' }
	$Files = @($places | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
	if (-not $Files) {
		$stderr.WriteLine('mobaxterm: no MobaXterm.ini in %APPDATA%\MobaXterm, for the portable edition pass the MobaXterm.ini next to MobaXterm.exe')
		$stdout.WriteLine('{"hosts":[]}')
		$stdout.Flush()
		exit 0
	}
}

$hosts = New-Object System.Collections.ArrayList
$seen = @{}
foreach ($f in $Files) {
	if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
		$stderr.WriteLine("mobaxterm: $(Clean $f) is not a file")
		exit 1
	}
	$item = Get-Item -LiteralPath $f
	# a link in a synced folder can point at any file
	if ($item.LinkType) {
		$stderr.WriteLine("mobaxterm: $(Clean $f) is a link, it is skipped")
		continue
	}
	if ($item.Length -gt 4MB) {
		$stderr.WriteLine("mobaxterm: $(Clean $f) is over 4 MiB, it is skipped")
		continue
	}
	# a .moba file is one session line without a section
	$section = if ($f -match '\.moba$') { 'Bookmarks' } else { '' }
	$folder = ''
	foreach ($line in (ReadText $f) -split "`r?`n") {
		if ($line -match '^\[(.*)\]$') {
			$section = $Matches[1]
			$folder = ''
			continue
		}
		if ($section -notmatch '^Bookmarks(_[0-9]+)?$') { continue }
		if ($line -match '^SubRep=(.*)$') { $folder = $Matches[1]; continue }
		# a name may hold =, the value starts with the reconnect flag, which
		# has none, and #icon#
		if ($line -notmatch '^(.+?)=([^=#]*#[0-9]+#.*)$') { continue }
		$name = $Matches[1].Trim()
		$value = $Matches[2]
		$parts = $value.Split('#')
		if ($parts.Count -lt 3) { continue }
		$g = $parts[2].Split('%')
		# type 0 is SSH, the others are RDP, VNC, SFTP and so on
		if ($g.Count -lt 4 -or $g[0] -ne '0') { continue }
		$hostName = Clean $g[1]
		$label = Clean $name
		if ($hostName -eq '' -or $label -eq '') { continue }
		# the folder keeps two sessions of one name in two folders apart
		$cleanFolder = Clean $folder
		$key = if ($cleanFolder -ne '') { $cleanFolder + '\' + $label } else { $label }
		if ($seen.ContainsKey($key)) { continue }
		$seen[$key] = $true
		$h = [ordered]@{ key = $key; name = $label; host = $hostName }
		if (OkPort $g[2]) { $h.port = [int]$g[2] }
		# <default> is the login set in MobaXterm, the Windows user unless changed
		$user = Clean $g[3]
		if ($user -ne '' -and $user -ne '<default>') { $h.user = $user }
		$keyFile = if ($g.Count -gt 14) { KeyPath $g[14] } else { '' }
		if ($keyFile -match '\.ppk$') {
			$stderr.WriteLine("mobaxterm: ${label}: the key $keyFile is a PuTTY key, convert it with puttygen key.ppk -O private-openssh -o key and set it in sshr")
		} elseif ($keyFile -ne '') {
			$h.key_file = $keyFile
		}
		if ($g.Count -gt 10) {
			$jump = Jumps $g[8] $g[9] $g[10]
			if ($jump -ne '') { $h.jump = $jump }
		}
		if ($g.Count -gt 19 -and $g[19] -ne '' -and $g[19] -ne '0') {
			$stderr.WriteLine("mobaxterm: ${label}: its proxy (type $(Clean $g[19])) is not carried, sshr goes direct or through jump hosts")
		}
		# in parentheses: clean at the start of a script block is the keyword
		# of a clean block in PowerShell 7.3 and later
		$tags = @($folder -split '\\' | ForEach-Object { (Clean $_) } | Where-Object { $_ -ne '' })
		if ($tags.Count -gt 0) { $h.tags = $tags }
		[void]$hosts.Add($h)
	}
}

$stdout.WriteLine((ConvertTo-Json -InputObject ([ordered]@{ hosts = $hosts }) -Depth 4 -Compress))
$stdout.Flush()
