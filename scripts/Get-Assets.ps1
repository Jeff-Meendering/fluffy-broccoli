$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$projectDir = Split-Path $PSScriptRoot -Parent
$buildDir = Join-Path $projectDir '.build-tools'
$assetsDir = Join-Path $projectDir 'assets'
New-Item -ItemType Directory -Force $buildDir, "$assetsDir/models", "$assetsDir/worker" | Out-Null
function Fetch($Url, $Destination, $Hash = '', $Algorithm = 'SHA256') {
    if (!(Test-Path -LiteralPath $Destination)) {
        $partial = $Destination + '.' + [Guid]::NewGuid().ToString('N') + '.download'
        try {
            Invoke-WebRequest $Url -OutFile $partial
            if ($Hash -and (Get-FileHash -LiteralPath $partial -Algorithm $Algorithm).Hash -ne $Hash) { throw "Checksum mismatch: $Destination" }
            Move-Item -LiteralPath $partial -Destination $Destination
        } finally {
            if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial }
        }
    }
    if ($Hash -and (Get-FileHash -LiteralPath $Destination -Algorithm $Algorithm).Hash -ne $Hash) {
        throw "Checksum mismatch: $Destination"
    }
}
$jdkName = 'OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip'
Fetch "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/$jdkName" "$buildDir/$jdkName" 'f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e'
if (!(Test-Path "$buildDir/jdk-21.0.12.1+1/bin/javac.exe")) { Expand-Archive -LiteralPath "$buildDir/$jdkName" -DestinationPath $buildDir -Force }
Fetch 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jre_x64_linux_hotspot_21.0.12.1_1.tar.gz' "$buildDir/linux-jre.tar.gz" '2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500'
$tikaUrl = 'https://repo.maven.apache.org/maven2/org/apache/tika/tika-app/3.3.2/tika-app-3.3.2.jar'
Fetch $tikaUrl "$assetsDir/worker/tika-app.jar" '71ca551380e5eab1add99101f4597a8a49a6a18c6143d6874ee9599ca10ae00e'
$ocrInstaller = 'tesseract-ocr-w64-setup-5.5.3.20260724.exe'
Fetch "https://github.com/tesseract-ocr/tesseract/releases/download/5.5.3/$ocrInstaller" "$buildDir/$ocrInstaller" 'bee9e3434bd94fd65387d9be28cd467a41f61b1275383b55b0f59a1331270ae4'
New-Item -ItemType Directory -Force "$buildDir/tessdata-fast-4.1.0" | Out-Null
Fetch 'https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/4.1.0/eng.traineddata' "$buildDir/tessdata-fast-4.1.0/eng.traineddata" '7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2'
Fetch 'https://raw.githubusercontent.com/tesseract-ocr/tessdata_fast/4.1.0/osd.traineddata' "$buildDir/tessdata-fast-4.1.0/osd.traineddata" '9cf5d576fcc47564f11265841e5ca839001e7e6f38ff7f7aacf46d15a96b00ff'
$revision = '3a19fe9404a4469d91aa3d551558a97f68872f67'
$modelUrl = "https://huggingface.co/onnx-community/distilbert-NER-ONNX/resolve/$revision"
# Pin every input, including non-LFS tokenizer/config files. Runtime downloads
# must not depend on a mutable metadata API or silently skip non-LFS hashes.
$modelHashes = @{
    'onnx/model_quantized.onnx' = '9419a876387ff2bbe5f21ab7429c7bef93eac86c50353390d4d8fca6e4a210d8'
    'vocab.txt' = 'eeaa9875b23b04b4c54ef759d03db9d1ba1554838f8fb26c5d96fa551df93d02'
    'config.json' = 'f109facddb205dac712adf5877e4315fae62041bc0916fe808d92abdb594d1fe'
    'tokenizer_config.json' = '3c02f7e3bd40e2aca0235ca42256609fd0cd7d883226e17ddea667f1b1314665'
    'README.md' = 'e0833c918d787ef6b82b62a2bb78640bdbc317156ec4bddef0e179791736cae4'
}
foreach ($file in @('onnx/model_quantized.onnx', 'vocab.txt', 'config.json', 'tokenizer_config.json', 'README.md')) {
    $name = Split-Path $file -Leaf
    Fetch "$modelUrl/$file" "$assetsDir/models/$name" $modelHashes[$file]
}
Get-ChildItem "$assetsDir/models", "$assetsDir/worker" -File | Get-FileHash | Select-Object Path,Hash | ConvertTo-Json | Set-Content "$assetsDir/hashes.json"
Write-Output 'Build assets downloaded and checked.'
