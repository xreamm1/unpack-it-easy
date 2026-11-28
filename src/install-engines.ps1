param([Parameter(Mandatory=$true)][string]$Root, [ValidateSet('detect','python','native','dotnet','java','retdec')][string]$Route='detect')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Net.Http
New-Item -ItemType Directory -Force -Path $Root | Out-Null
$Root = (Resolve-Path -LiteralPath $Root).Path
$cache = Join-Path $Root 'downloads'
New-Item -ItemType Directory -Force -Path $cache | Out-Null

function File-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '') }
    finally { $sha.Dispose(); $stream.Dispose() }
}

function Find-Binary([string]$Directory, [string]$Name) {
    if (Test-Path -LiteralPath $Directory) {
        $match = Get-ChildItem -LiteralPath $Directory -Filter $Name -File -Recurse | Select-Object -First 1
        if ($match) { return $match.FullName }
    }
    return ''
}

function Fetch([string]$Url, [string]$Path, [string]$Hash='') {
    if (Test-Path -LiteralPath $Path) {
        if ((Get-Item -LiteralPath $Path).Length -gt 0 -and (!$Hash -or (File-Sha256 $Path) -eq $Hash)) { return }
    }
    Write-Host "Downloading $Url"
    $client = New-Object System.Net.Http.HttpClient
    $client.Timeout = [TimeSpan]::FromMinutes(30)
    $response = $null
    $inputStream = $null
    $outputStream = $null
    try {
        $response = $client.GetAsync($Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $response.EnsureSuccessStatusCode() | Out-Null
        $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $outputStream = [IO.File]::Create($Path + '.part')
        $buffer = New-Object byte[] 1048576
        $total = 0L
        $lastReport = 0L
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $outputStream.Write($buffer, 0, $read)
            $total += $read
            if ($total - $lastReport -ge 8388608) {
                Write-Host ("Downloaded {0:N0} MiB" -f ($total / 1MB))
                $lastReport = $total
            }
        }
        $outputStream.Dispose(); $outputStream = $null
        if ($total -eq 0) { throw 'Empty download' }
        if ($Hash -and (File-Sha256 ($Path + '.part')) -ne $Hash) { throw 'SHA256 mismatch' }
        Move-Item -LiteralPath ($Path + '.part') -Destination $Path -Force
    } finally {
        if ($outputStream) { $outputStream.Dispose() }
        if ($inputStream) { $inputStream.Dispose() }
        if ($response) { $response.Dispose() }
        $client.Dispose()
    }
}

function Release-Zip([string]$Repository, [string]$Pattern, [string]$Destination) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/latest" -Headers @{'User-Agent'='UIE'}
    $asset = $release.assets | Where-Object { $_.name -match $Pattern } | Select-Object -First 1
    if (!$asset) { throw "No matching archive in $Repository" }
    $archive = Join-Path $cache $asset.name
    $hash = ''
    if ($asset.digest -and $asset.digest.StartsWith('sha256:')) { $hash = $asset.digest.Substring(7) }
    Fetch $asset.browser_download_url $archive $hash
    Write-Host "Extracting $($asset.name)"
    Expand-Archive -LiteralPath $archive -DestinationPath $Destination -Force
}

function Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Tool returned $LASTEXITCODE : $Program" }
}

$manifest = @{}
$manifestPath = Join-Path $Root 'engines.json'
if (Test-Path -LiteralPath $manifestPath) {
    $old = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    foreach ($property in $old.PSObject.Properties) { $manifest[$property.Name] = $property.Value }
}

$die = Find-Binary (Join-Path $Root 'die') 'diec.exe'
if (!$die) {
    try {
        Release-Zip 'horsicq/DIE-engine' '^die_win64_[0-9.]+\.zip$' (Join-Path $Root 'die')
        $die = Find-Binary (Join-Path $Root 'die') 'diec.exe'
    } catch { Write-Host "DIE download unavailable; using built-in detection: $_" }
}
$manifest['diec'] = $die

if ($Route -eq 'python') {
    $uv = Find-Binary (Join-Path $Root 'uv') 'uv.exe'
    if (!$uv) {
        Release-Zip 'astral-sh/uv' '^uv-x86_64-pc-windows-msvc\.zip$' (Join-Path $Root 'uv')
        $uv = Find-Binary (Join-Path $Root 'uv') 'uv.exe'
    }
    $env:UV_PYTHON_INSTALL_DIR = Join-Path $Root 'python'
    $env:UV_PYTHON_BIN_DIR = Join-Path $Root 'python-bin'
    $env:UV_CACHE_DIR = Join-Path $Root 'cache'
    $env:PYTHONIOENCODING = 'utf-8'
    $env:PYTHONUTF8 = '1'
    Write-Host 'Preparing embedded Python 3.12'
    Checked $uv @('python','install','3.12')
    $python = (& $uv python find --managed-python 3.12 | Select-Object -Last 1).Trim()
    if (!(Test-Path -LiteralPath $python)) { throw 'Managed Python not found' }
    $pythonDirectory = Get-Item -LiteralPath (Split-Path $python)
    if ($pythonDirectory.LinkType -eq 'Junction') { $python = Join-Path @($pythonDirectory.Target)[0] 'python.exe' }
    $sources = Join-Path $Root 'sources'
    $pylingualSource = Join-Path $sources 'pylingual-11a1516d84a6c2aa71ec23fbd11e4b99dc8c4a86'
    $xdisSource = Join-Path $sources 'python-xdis-35d8df26622903e57c97a797cb7fefd2f0338267'
    if (!(Test-Path -LiteralPath $pylingualSource)) {
        Fetch 'https://codeload.github.com/syssec-utd/pylingual/zip/11a1516d84a6c2aa71ec23fbd11e4b99dc8c4a86' (Join-Path $cache 'pylingual-source.zip')
        Expand-Archive -LiteralPath (Join-Path $cache 'pylingual-source.zip') -DestinationPath $sources -Force
    }
    if (!(Test-Path -LiteralPath $xdisSource)) {
        Fetch 'https://codeload.github.com/rocky/python-xdis/zip/35d8df26622903e57c97a797cb7fefd2f0338267' (Join-Path $cache 'xdis-source.zip')
        Expand-Archive -LiteralPath (Join-Path $cache 'xdis-source.zip') -DestinationPath $sources -Force
    }
    Write-Host 'Installing local decompiler and extractor'
    Checked $uv @('pip','install','--python',$python,'--break-system-packages','--no-sources',$pylingualSource,$xdisSource,'pycryptodome')
    Checked $uv @('pip','install','--python',$python,'--break-system-packages','--no-deps','pyinstxtractor-ng')
    Checked $python @('-c','import pylingual, pyinstxtractor_ng, torch')
    Write-Host 'Python engines ready'
    $manifest['python'] = $python
    $manifest['pylingual'] = $python
    $manifest['extractor'] = $python
    $manifest['uv'] = $uv
}

$javaMajor = 21
if ($Route -eq 'native') {
    $ghidra = Find-Binary (Join-Path $Root 'ghidra') 'analyzeHeadless.bat'
    if (!$ghidra) {
        Release-Zip 'NationalSecurityAgency/ghidra' '^ghidra_.*PUBLIC.*\.zip$' (Join-Path $Root 'ghidra')
        $ghidra = Find-Binary (Join-Path $Root 'ghidra') 'analyzeHeadless.bat'
    }
    if (!$ghidra) { throw 'Ghidra launcher missing' }
    $properties = Join-Path (Split-Path (Split-Path $ghidra)) 'Ghidra/application.properties'
    $javaMajor = 21
    if (Test-Path -LiteralPath $properties) {
        $javaLine = Get-Content -LiteralPath $properties | Where-Object { $_ -match '^application\.java\.min=' } | Select-Object -First 1
        if ($javaLine -match '=(\d+)') { $javaMajor = [int]$Matches[1] }
    }
    $manifest['ghidra'] = $ghidra
}
if ($Route -in @('native','java')) {
    $java = Find-Binary (Join-Path $Root 'java') 'java.exe'
    if (!$java) {
        $assets = Invoke-RestMethod "https://api.adoptium.net/v3/assets/latest/$javaMajor/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse"
        $package = @($assets)[0].binary.package
        $archive = Join-Path $cache 'jdk.zip'
        Fetch $package.link $archive $package.checksum
        Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $Root 'java') -Force
        $java = Find-Binary (Join-Path $Root 'java') 'java.exe'
    }
    if (!$java) { throw 'Embedded Java missing' }
    $manifest['java_home'] = Split-Path (Split-Path $java)
}

if ($Route -eq 'dotnet') {
    $ilspy = Find-Binary (Join-Path $Root 'ilspy') 'ilspycmd.exe'
    if (!$ilspy) { $ilspy = Find-Binary (Join-Path $Root 'ilspy') 'ilspycmd.dll' }
    if (!$ilspy) {
        $index = Invoke-RestMethod 'https://api.nuget.org/v3-flatcontainer/ilspycmd/index.json'
        $version = @($index.versions | Where-Object { $_ -notmatch '-' })[-1]
        $archive = Join-Path $cache 'ilspycmd.zip'
        Fetch "https://api.nuget.org/v3-flatcontainer/ilspycmd/$version/ilspycmd.$version.nupkg" $archive
        Expand-Archive -LiteralPath $archive -DestinationPath (Join-Path $Root 'ilspy') -Force
        $toolSettings = Find-Binary (Join-Path $Root 'ilspy') 'DotnetToolSettings.xml'
        if ($toolSettings) {
            [xml]$toolXml = Get-Content -Raw -LiteralPath $toolSettings
            $runtimePackage = $toolXml.DotNetCliTool.RuntimeIdentifierPackages.RuntimeIdentifierPackage | Where-Object { $_.RuntimeIdentifier -eq 'win-x64' } | Select-Object -First 1
            if ($runtimePackage) {
                $id = $runtimePackage.Id.ToLowerInvariant()
                $runtimeArchive = Join-Path $cache 'ilspycmd-win-x64.zip'
                Fetch "https://api.nuget.org/v3-flatcontainer/$id/$version/$id.$version.nupkg" $runtimeArchive
                Expand-Archive -LiteralPath $runtimeArchive -DestinationPath (Join-Path $Root 'ilspy/runtime') -Force
            }
        }
        $ilspy = Find-Binary (Join-Path $Root 'ilspy') 'ilspycmd.exe'
        if (!$ilspy) { $ilspy = Find-Binary (Join-Path $Root 'ilspy') 'ilspycmd.dll' }
    }
    if (!$ilspy) { throw 'ILSpy CLI missing' }
    $runtimeFile = Join-Path (Split-Path $ilspy) 'ilspycmd.runtimeconfig.json'
    if (Test-Path -LiteralPath $runtimeFile) {
    $runtimeConfig = Get-Content -Raw -LiteralPath $runtimeFile | ConvertFrom-Json
    $runtimeVersion = $runtimeConfig.runtimeOptions.framework.version
    if (!$runtimeVersion) { $runtimeVersion = @($runtimeConfig.runtimeOptions.frameworks)[0].version }
    if (!$runtimeVersion) { throw 'Unknown .NET runtime version' }
    $channel = ($runtimeVersion.Split('.')[0]) + '.0'
    $dotnet = Join-Path $Root 'dotnet'
    if (!(Test-Path -LiteralPath (Join-Path $dotnet 'dotnet.exe'))) {
        $installer = Join-Path $cache 'dotnet-install.ps1'
        Fetch 'https://dot.net/v1/dotnet-install.ps1' $installer
        & $installer -Runtime dotnet -Channel $channel -Architecture x64 -InstallDir $dotnet -NoPath
        if (!$?) { throw '.NET runtime install failed' }
    }
    $manifest['ilspy'] = $ilspy
    $manifest['dotnet_root'] = $dotnet
    }
    $manifest['ilspy'] = $ilspy
}

if ($Route -eq 'retdec') {
    $retdecRoot = Join-Path $Root 'retdec'
    $retdec = Join-Path $retdecRoot 'bin/retdec-decompiler.exe'
    if (!(Test-Path -LiteralPath $retdec) -or !(Test-Path -LiteralPath (Join-Path $retdecRoot 'share/retdec/support')) -or !(Test-Path -LiteralPath (Join-Path $retdecRoot 'LICENSE-THIRD-PARTY'))) {
        $archive = Join-Path $cache 'RetDec-v5.0-Windows-Release.7z'
        Fetch 'https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Windows-Release.7z' $archive '496a2d86420115eaa21ac8ff9b202282525f0a46a28a78c983f2cca0643ab101'
        New-Item -ItemType Directory -Path $retdecRoot -Force | Out-Null
        Checked (Join-Path $env:SystemRoot 'System32/tar.exe') @('-xf',$archive,'-C',$retdecRoot,'bin','share','LICENSE','LICENSE-PELIB','LICENSE-THIRD-PARTY','README.md','CHANGELOG.md')
    }
    if (!(Test-Path -LiteralPath $retdec)) { throw 'RetDec executable missing' }
    $crypto = Join-Path $retdecRoot 'bin/libcrypto-1_1-x64.dll'
    if (!(Test-Path -LiteralPath $crypto) -or !(Test-Path -LiteralPath (Join-Path $retdecRoot 'licenses/Python-OpenSSL-LICENSE.txt')) -or !(Test-Path -LiteralPath (Join-Path $retdecRoot 'licenses/OpenSSL-1.1.1-LICENSE.txt'))) {
        $uv = Find-Binary (Join-Path $Root 'uv') 'uv.exe'
        if (!$uv) {
            Release-Zip 'astral-sh/uv' '^uv-x86_64-pc-windows-msvc\.zip$' (Join-Path $Root 'uv')
            $uv = Find-Binary (Join-Path $Root 'uv') 'uv.exe'
        }
        if (!$uv) { throw 'Managed Python installer missing for RetDec OpenSSL dependency' }
        $env:UV_PYTHON_INSTALL_DIR = Join-Path $Root 'python'
        $env:UV_PYTHON_BIN_DIR = Join-Path $Root 'python-bin'
        $env:UV_CACHE_DIR = Join-Path $Root 'cache'
        Checked $uv @('python','install','3.8')
        $python38 = (& $uv python find --managed-python 3.8 | Select-Object -Last 1).Trim()
        if (!(Test-Path -LiteralPath $python38)) { throw 'Managed Python 3.8 dependency not found' }
        $python38Root = Split-Path $python38
        $cryptoSource = Join-Path $python38Root 'DLLs/libcrypto-1_1-x64.dll'
        if (!(Test-Path -LiteralPath $cryptoSource)) { throw 'Official managed Python is missing the required OpenSSL DLL' }
        $licenseRoot = Join-Path $retdecRoot 'licenses'
        New-Item -ItemType Directory -Path $licenseRoot -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $python38Root 'LICENSE.txt') -Destination (Join-Path $licenseRoot 'Python-OpenSSL-LICENSE.txt') -Force
        Fetch 'https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_1_1w/LICENSE' (Join-Path $licenseRoot 'OpenSSL-1.1.1-LICENSE.txt') 'c32913b33252e71190af2066f08115c69bc9fddadf3bf29296e20c835389841c'
        Copy-Item -LiteralPath $cryptoSource -Destination $crypto -Force
    }
    Checked $retdec @('--version')
    $manifest['retdec'] = $retdec
}

$merged = @{}
if (Test-Path -LiteralPath $manifestPath) {
    $latest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    foreach ($property in $latest.PSObject.Properties) { $merged[$property.Name] = $property.Value }
}
foreach ($key in $manifest.Keys) { $merged[$key] = $manifest[$key] }
foreach ($key in @($merged.Keys)) {
    $value = [string]$merged[$key]
    if ($value.StartsWith($Root + '\', [StringComparison]::OrdinalIgnoreCase)) { $merged[$key] = $value.Substring($Root.Length + 1) }
}
[IO.File]::WriteAllText($manifestPath, ($merged | ConvertTo-Json), (New-Object Text.UTF8Encoding($false)))
Write-Host "Managed engines ready: $Route"
