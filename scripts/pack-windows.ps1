$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$root    = 'C:\Users\steve\ai_completion\nomount-manager'
$mod     = Join-Path $root 'module'
$freshBin= Join-Path $root 'target\aarch64-linux-android\release\nomount'
$oldZip  = Join-Path $root 'release\release\nomount-v2.3.15.zip'

$ver = (Select-String -Path (Join-Path $mod 'module.prop') -Pattern '^version=(.+)$').Matches[0].Groups[1].Value
Write-Host "version: $ver"

# The header/footer in the WebUI report `nomount version`, i.e. the version compiled
# into the binary (CARGO_PKG_VERSION) — not module.prop. Bumping module.prop for a
# webroot-only change without rebuilding therefore ships a binary that self-reports an
# older version, and the UI shows the stale one. Refuse to package in that state.
$bare = $ver -replace '^v', ''
$bytes = [IO.File]::ReadAllBytes($freshBin)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
if ($ascii -notmatch [regex]::Escape($bare)) {
    throw "binary at $freshBin does not contain version '$bare' — rebuild it (cargo build --release --target aarch64-linux-android) before packaging $ver"
}
Write-Host "binary embeds version $bare - ok"

$stage = Join-Path $env:TEMP ("nmpack_" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'bin\arm64-v8a') | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'webroot') | Out-Null

# text files: copy with CRLF -> LF (module scripts must be LF on Android)
function Copy-Lf($src, $dst) {
    $b = [IO.File]::ReadAllBytes($src)
    $out = New-Object 'System.Collections.Generic.List[byte]'
    foreach ($x in $b) { if ($x -ne 13) { $out.Add($x) } }
    [IO.File]::WriteAllBytes($dst, $out.ToArray())
}

foreach ($f in @('customize.sh','metamount.sh','post-fs-data.sh','service.sh','module.prop')) {
    Copy-Lf (Join-Path $mod $f) (Join-Path $stage $f)
}
foreach ($f in @('config.json','index.html')) {
    Copy-Lf (Join-Path $mod "webroot\$f") (Join-Path $stage "webroot\$f")
}
Copy-Item (Join-Path $mod 'webroot\icon.png') (Join-Path $stage 'webroot\icon.png')
Copy-Item (Join-Path $mod 'bin\arm64-v8a\nm') (Join-Path $stage 'bin\arm64-v8a\nm')
Copy-Item $freshBin (Join-Path $stage 'bin\arm64-v8a\nomount')

# META-INF (installer shim) carried over from the previous release
$z = [IO.Compression.ZipFile]::OpenRead($oldZip)
foreach ($e in $z.Entries) {
    if ($e.FullName -like 'META-INF/*') {
        $dst = Join-Path $stage ($e.FullName -replace '/', '\')
        New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
        [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $dst, $true)
    }
}
$z.Dispose()

# checksums over payload (not META-INF, not the sums file itself)
$payload = @(
    'bin/arm64-v8a/nm','bin/arm64-v8a/nomount','customize.sh','metamount.sh',
    'module.prop','post-fs-data.sh','service.sh',
    'webroot/config.json','webroot/icon.png','webroot/index.html'
)
$lines = foreach ($rel in $payload) {
    $p = Join-Path $stage ($rel -replace '/', '\')
    $h = (Get-FileHash -Algorithm SHA256 -Path $p).Hash.ToLower()
    # TEXT mode: two spaces, no asterisk. The "<hash> *path" binary-mode marker
    # is accepted by busybox and coreutils but NOT by Android's toybox, which
    # reads the asterisk as the first character of the filename and fails every
    # entry -- and customize.sh aborts the install when the check fails.
    "$h  ./$rel"
}
[IO.File]::WriteAllText((Join-Path $stage 'nomount.sha256sums'), (($lines -join "`n") + "`n"))

# zip: explicit CreateEntry with forward slashes (Compress-Archive writes backslashes)
$order = @(
    'customize.sh','metamount.sh','post-fs-data.sh','service.sh','module.prop',
    'bin/arm64-v8a/nm','bin/arm64-v8a/nomount',
    'webroot/config.json','webroot/icon.png','webroot/index.html',
    'nomount.sha256sums',
    'META-INF/com/google/android/update-binary','META-INF/com/google/android/updater-script'
)
$outDir = Join-Path $root 'release\release'
$outZip = Join-Path $outDir ("nomount-$ver.zip")
if (Test-Path $outZip) { Remove-Item $outZip -Force }
$fs = [IO.File]::Open($outZip, [IO.FileMode]::CreateNew)
$zip = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
foreach ($rel in $order) {
    $src = Join-Path $stage ($rel -replace '/', '\')
    if (-not (Test-Path $src)) { throw "missing staged file: $rel" }
    $entry = $zip.CreateEntry($rel, [IO.Compression.CompressionLevel]::Optimal)
    $es = $entry.Open()
    $bytes = [IO.File]::ReadAllBytes($src)
    $es.Write($bytes, 0, $bytes.Length)
    $es.Close()
}
$zip.Dispose(); $fs.Close()
Remove-Item -Recurse -Force $stage

Write-Host "built: $outZip ($((Get-Item $outZip).Length) bytes)"
Write-Host "OUTZIP=$outZip"
