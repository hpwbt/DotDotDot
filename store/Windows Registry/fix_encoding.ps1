# Fix the two problematic registry files

$files = @(
    'Prevent Downloaded Files from Being Blocked.reg',
    'Prevent Windows from Reducing Wallpaper Quality.reg'
)

$registryDir = 'C:\Users\hpwbt\Dotfiles\store\Windows Registry'

foreach ($fileName in $files) {
    $filePath = Join-Path $registryDir $fileName

    Write-Host "Fixing: $fileName"

    # Read the content as UTF-8 (current encoding)
    $content = Get-Content -LiteralPath $filePath -Raw -Encoding UTF8

    # Remove any BOM characters that might be present
    $content = $content.Trim([char]0xFEFF)

    # Ensure it starts with the correct header
    if (-not $content.StartsWith('Windows Registry Editor Version 5.00')) {
        Write-Host "  Warning: File doesn't start with correct header. Adding it..." -ForegroundColor Yellow
        # Remove any leading whitespace or empty lines
        $content = $content.TrimStart()
        # If it's completely empty or doesn't have the header, prepend it
        if ([string]::IsNullOrWhiteSpace($content) -or -not $content.StartsWith('Windows Registry Editor')) {
            $content = "Windows Registry Editor Version 5.00`r`n`r`n" + $content
        }
    }

    # Ensure proper line endings (CRLF)
    $content = $content -replace "`r`n", "`n" -replace "`n", "`r`n"

    # Write as UTF-16 LE with BOM
    [System.IO.File]::WriteAllText($filePath, $content, [System.Text.Encoding]::Unicode)

    Write-Host "  Converted to UTF-16 LE" -ForegroundColor Green
}

Write-Host "`nVerifying fixes..."

# Re-run the diagnostic
foreach ($fileName in $files) {
    $filePath = Join-Path $registryDir $fileName

    Write-Host "`nVerifying: $fileName"

    # Check BOM
    $bytes = [System.IO.File]::ReadAllBytes($filePath)
    if ($bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        Write-Host "  BOM: UTF-16 LE ✓" -ForegroundColor Green
    } else {
        Write-Host "  BOM: Still wrong!" -ForegroundColor Red
    }

    # Check first line
    $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::Unicode)
    $firstLine = $content.Split("`n")[0].Trim()
    if ($firstLine -eq 'Windows Registry Editor Version 5.00') {
        Write-Host "  First line: Correct ✓" -ForegroundColor Green
    } else {
        Write-Host "  First line: '$firstLine'" -ForegroundColor Red
    }

    # Test import
    $testOutput = & reg.exe import $filePath 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Import: Success ✓" -ForegroundColor Green
    } else {
        Write-Host "  Import: Failed" -ForegroundColor Red
    }
}