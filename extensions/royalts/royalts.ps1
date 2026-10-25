# sshr ext import royalts <file.rtsz>... reads the SSH connections of Royal
# TS documents on Windows and prints them as {"hosts": [...]} for sshr, the
# same as royalts.sh does on Linux and macOS
#
# A document is XML (.rtsx, or .rtsz saved without a zip) or a zip that
# holds the XML as Document.rtsz, the root RTSZDocument holds a flat list
# of objects linked by ID and ParentID, every property is a child element,
# the folders above a connection become tags, a connection in the trash, a
# template or a telnet connection is left out, passwords stay encrypted in
# the document and are never read, a key embedded in the document is left
# out with a note
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Files)

$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$stdout = New-Object System.IO.StreamWriter([Console]::OpenStandardOutput(), $utf8)
$stderr = New-Object System.IO.StreamWriter([Console]::OpenStandardError(), $utf8)
$stderr.AutoFlush = $true

if ($env:SSHR_EXT_PROTOCOL -ne '1') {
	$stderr.WriteLine('royalts: run me with sshr ext import royalts, not by hand')
	exit 2
}
if (-not $Files -or $Files.Count -eq 0) {
	$stderr.WriteLine('royalts: give the Royal TS documents to read, sshr ext import royalts C:\Users\me\Documents\servers.rtsz')
	exit 1
}

# Clean drops control characters, DEL and the C1 controls, a document may
# carry any of them and they would drive the terminal
function Clean([string]$s) {
	$out = New-Object System.Text.StringBuilder
	foreach ($c in "$s".ToCharArray()) {
		$n = [int]$c
		if ($n -lt 32 -or ($n -ge 127 -and $n -le 159)) { continue }
		[void]$out.Append($c)
	}
	$out.ToString().Trim()
}

function OkPort($p) {
	$n = 0
	"$p" -match '^[0-9]+$' -and [int]::TryParse("$p", [ref]$n) -and $n -ge 1 -and $n -le 65535
}

function Text($el, [string]$name) {
	$c = $el[$name]
	if ($null -eq $c) { return '' }
	Clean $c.InnerText
}

# ReadXml is the text of the document, the Document.rtsz entry of a zip
function ReadXml([string]$path) {
	$head = New-Object byte[] 2
	$fs = [System.IO.File]::OpenRead($path)
	try { [void]$fs.Read($head, 0, 2) } finally { $fs.Close() }
	if ($head[0] -ne 0x50 -or $head[1] -ne 0x4B) {
		return [System.IO.File]::ReadAllText($path)
	}
	Add-Type -AssemblyName System.IO.Compression.FileSystem
	$zip = [System.IO.Compression.ZipFile]::OpenRead($path)
	try {
		$entry = $zip.GetEntry('Document.rtsz')
		if ($null -eq $entry) { $entry = $zip.Entries | Select-Object -First 1 }
		$reader = New-Object System.IO.StreamReader($entry.Open())
		try { return $reader.ReadToEnd() } finally { $reader.Close() }
	} finally { $zip.Dispose() }
}

$hosts = New-Object System.Collections.ArrayList
$secrets = 0
$doc = 0
foreach ($f in $Files) {
	$doc++
	if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
		$stderr.WriteLine("royalts: $(Clean $f) is no file")
		exit 1
	}
	if ((Get-Item -LiteralPath $f).Length -gt 33554432) {
		$stderr.WriteLine("royalts: $(Clean $f) is over 32 MiB, it is skipped")
		continue
	}
	# no DTD and no external entities, a document is data from elsewhere
	$settings = New-Object System.Xml.XmlReaderSettings
	$settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
	$settings.XmlResolver = $null
	$reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader (ReadXml $f)), $settings)
	$xml = New-Object System.Xml.XmlDocument
	$xml.XmlResolver = $null
	$xml.Load($reader)
	$reader.Close()
	if ($xml.DocumentElement.Name -ne 'RTSZDocument') {
		$stderr.WriteLine("royalts: $(Clean $f) is no Royal TS document")
		exit 1
	}
	$objs = @{}
	$byName = @{}
	foreach ($el in $xml.DocumentElement.ChildNodes) {
		if ($el.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
		$id = Text $el 'ID'
		if ($id -eq '') { continue }
		$objs[$id] = $el
		if ($el.Name -eq 'RoyalCredential') {
			$n = Text $el 'Name'
			if ($n -ne '') { $byName[$n] = Text $el 'UserName' }
			if ((Text $el 'Password') -ne '') { $secrets++ }
		} elseif ((Text $el 'CredentialPassword') -ne '') { $secrets++ }
	}
	function UserOf($el, [int]$hops) {
		if ($null -eq $el -or $hops -gt 32) { return '' }
		$mode = Text $el 'CredentialMode'
		if ((Text $el 'CredentialFromParent') -eq 'True' -or $mode -eq '1') { return UserOf $objs[(Text $el 'ParentID')] ($hops + 1) }
		$u = Text $el 'CredentialUsername'
		if ($mode -eq '3') { $c = $objs[(Text $el 'CredentialId')]; $u = if ($c) { Text $c 'UserName' } else { '' } }
		elseif ($mode -eq '4') { $u = "$($byName[(Text $el 'CredentialName')])" }
		$d = $u.IndexOf('\')
		if ($d -ge 0) { $u = $u.Substring($d + 1) }
		$u
	}
	foreach ($el in $objs.Values) {
		if ($el.Name -ne 'RoyalSSHConnection') { continue }
		if ((Text $el 'IsTelnetConnection') -eq 'True' -or (Text $el 'IsConnectionTemplate') -eq 'True') { continue }
		$tags = New-Object System.Collections.ArrayList
		$trash = $false
		$pid2 = Text $el 'ParentID'
		for ($i = 0; $i -lt 64 -and $objs.ContainsKey($pid2); $i++) {
			$p = $objs[$pid2]
			if ($p.Name -eq 'RoyalTrash') { $trash = $true; break }
			if ($p.Name -eq 'RoyalFolder' -and (Text $p 'Name') -ne '') { $tags.Insert(0, (Text $p 'Name')) }
			$pid2 = Text $p 'ParentID'
		}
		if ($trash) { continue }
		$hostName = Text $el 'URI'
		$port = Text $el 'Port'
		$user = UserOf $el 0
		$hostName = $hostName -replace '^[A-Za-z][A-Za-z0-9+.-]*://', '' -replace '/.*$', ''
		$at = $hostName.IndexOf('@')
		if ($at -ge 0) { if ($user -eq '') { $user = $hostName.Substring(0, $at) }; $hostName = $hostName.Substring($at + 1) }
		if ($hostName -match '^([^:]+):([0-9]+)$') { if ($port -eq '') { $port = $Matches[2] }; $hostName = $Matches[1] }
		if ($hostName -eq '') { continue }
		$name = Text $el 'Name'
		if ($name -eq '') { $name = $hostName }
		$h = [ordered]@{ key = 'royalts:' + (Text $el 'ID'); name = $name; host = $hostName }
		if (OkPort $port) { $h.port = [int]$port }
		if ($user -ne '') { $h.user = $user }
		if ((Text $el 'CredentialKeyMode') -eq '1' -or (Text $el 'CredentialKeyContent') -ne '') {
			$stderr.WriteLine("royalts: ${name}: its key is embedded in the document, save it as a file and set it in sshr")
		} elseif ((Text $el 'CredentialKeyFile') -ne '') {
			$h.key_file = Text $el 'CredentialKeyFile'
		}
		if ($tags.Count -gt 0) { $h.tags = @($tags) }
		[void]$hosts.Add($h)
	}
}
if ($secrets -gt 0) {
	$stderr.WriteLine("royalts: $secrets saved passwords stay in Royal TS, they are encrypted in the document and are not read")
}
$stdout.WriteLine((ConvertTo-Json -InputObject ([ordered]@{ hosts = $hosts }) -Depth 4 -Compress))
$stdout.Flush()
