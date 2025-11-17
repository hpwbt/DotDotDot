$files = @(
    'Prevent Downloaded Files from Being Blocked.reg',
    'Prevent Windows from Reducing Wallpaper Quality.reg'
)

foreach ($file in $files) {
    $path = Join-Path 'C:\Users\hpwbt\Dotfiles\store\Windows Registry' $file

    Write-Host "`nAnalyzing: $file"

    # Check if file exists
    if (-not (Test-Path $path)) {
        Write-Host "  File not found!" -ForegroundColor Red
        continue
    }

    # Read raw bytes
    $bytes = [System.IO.File]::ReadAllBytes($path)

    # Check BOM
    if ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        Write-Host "  BOM: UTF-16 LE (Correct!)" -ForegroundColor Green
    } elseif ($bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        Write-Host "  BOM: UTF-16 BE (Wrong! Should be LE)" -ForegroundColor Red
    } elseif ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-Host "  BOM: UTF-8 (Wrong! Should be UTF-16 LE)" -ForegroundColor Red
    } else {
        Write-Host "  BOM: None or unknown (Wrong! Should be UTF-16 LE)" -ForegroundColor Red
    }

    # Check first line
    $content = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::Unicode)
    $firstLine = $content.Split("`n")[0].Trim()

    if ($firstLine -eq 'Windows Registry Editor Version 5.00') {
        Write-Host "  First line: Correct" -ForegroundColor Green
    } else {
        Write-Host "  First line: '$firstLine' (Should be 'Windows Registry Editor Version 5.00')" -ForegroundColor Red
    }

    # Try importing
    Write-Host "  Testing import..."
    $testOutput = & reg.exe import $path 2>&1
    $testExit = $LASTEXITCODE

    if ($testExit -eq 0) {
        Write-Host "  Import: Success!" -ForegroundColor Green
    } else {
        Write-Host "  Import: Failed with exit code $testExit" -ForegroundColor Red
        Write-Host "  Error: $testOutput" -ForegroundColor Red
    }
}