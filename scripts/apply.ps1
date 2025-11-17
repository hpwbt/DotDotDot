Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Status code constants.
$StatusCodes = @{
    Succeeded = 'succeeded'
    Skipped   = 'skipped'
    Missing   = 'missing'
    Failed    = 'failed'
    Imported  = 'imported'
}

# Resolve repository paths.
$ScriptDirPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ParentDirPath = Split-Path $ScriptDirPath -Parent
$MapPath       = Join-Path $ParentDirPath "map.json"

# Verify we're running from inside %USERPROFILE%\Dotfiles
$ExpectedDirPath = Join-Path $env:USERPROFILE 'Dotfiles'
if ($ParentDirPath -ne $ExpectedDirPath) {
    Write-Host ("`nError: This script must be run from inside '{0}'." -f $ExpectedDirPath) -ForegroundColor Red
    Write-Host ("Current location: {0}" -f $ParentDirPath)
    Write-Host ("Expected location: {0}" -f $ExpectedDirPath)
    exit 1
}

# Require presence of the configuration file.
if (-not (Test-Path -LiteralPath $MapPath)) {
    throw "Map configuration file not found at: $MapPath"
}

# Check if an object has a specific property.
function Test-HasProperty {
    param(
        [Parameter(Mandatory=$true)]$Object,
        [Parameter(Mandatory=$true)][string]$PropertyName
    )
    $null -ne $Object.PSObject.Properties[$PropertyName]
}

# Validate that an object has a required property.
function Test-PropertyExists {
    param(
        [Parameter(Mandatory=$true)]$Object,
        [Parameter(Mandatory=$true)][string]$PropertyName,
        [Parameter(Mandatory=$true)][string]$Context
    )
    if (-not (Test-HasProperty -Object $Object -PropertyName $PropertyName)) {
        throw "$Context lacks a $PropertyName"
    }
}

# Validate that a value is a non-empty string.
function Test-NonEmptyString {
    param(
        [Parameter(Mandatory=$true)]$Value,
        [Parameter(Mandatory=$true)][string]$PropertyName,
        [Parameter(Mandatory=$true)][string]$Context
    )
    if (-not ($Value -is [string]) -or [string]::IsNullOrWhiteSpace($Value)) {
        throw "$Context $PropertyName must be a non-empty text value"
    }
}

# Validate that a value is a list.
function Test-IsList {
    param(
        [Parameter(Mandatory=$true)]$Value,
        [Parameter(Mandatory=$true)][string]$PropertyName,
        [Parameter(Mandatory=$true)][string]$Context
    )
    if (-not ($Value -is [System.Collections.IEnumerable]) -or ($Value -is [string])) {
        throw "$Context $PropertyName must be provided as a list"
    }
}

# Validate that a value is an object.
function Test-IsObject {
    param(
        [Parameter(Mandatory=$true)]$Value,
        [Parameter(Mandatory=$true)][string]$Context
    )
    if ($Value -isnot [PSCustomObject] -and $Value -isnot [hashtable]) {
        throw "$Context must be an object"
    }
}

# Validate a mapping object has required live and store properties.
function Assert-MappingObject {
    param(
        [Parameter(Mandatory=$true)]$Mapping,
        [Parameter(Mandatory=$true)][string]$MappingType
    )

    Test-IsObject -Value $Mapping -Context "$MappingType mapping"
    Test-PropertyExists -Object $Mapping -PropertyName 'live' -Context "$MappingType mapping"
    Test-PropertyExists -Object $Mapping -PropertyName 'store' -Context "$MappingType mapping"
    Test-NonEmptyString -Value $Mapping.live -PropertyName 'live path' -Context "$MappingType mapping"
    Test-NonEmptyString -Value $Mapping.store -PropertyName 'store path' -Context "$MappingType mapping"
}

# Expand environment variable tokens in text.
function Expand-EnvTokens {
    param([Parameter(Mandatory=$true)][string]$Text)

    $pattern = '\$env:([A-Za-z0-9_]+)'
    [System.Text.RegularExpressions.Regex]::Replace($Text, $pattern, {
        param($match)
        $variableName = $match.Groups[1].Value
        $variableValue = [Environment]::GetEnvironmentVariable($variableName)
        if ($null -eq $variableValue) {
            throw "Unknown environment variable: $variableName"
        }
        $variableValue
    })
}

# Normalize slashes and resolve to a full path.
function Normalize-Path {
    param([Parameter(Mandatory=$true)][string]$Text)

    $windowsPath = $Text -replace '/', '\'
    [System.IO.Path]::GetFullPath($windowsPath)
}

# Resolve a path inside the program's store folder and block path traversal.
function Resolve-StorePath {
    param(
        [Parameter(Mandatory=$true)][string]$ProgramStoreRootPath,
        [Parameter(Mandatory=$true)][string]$RelativePath
    )

    $normalizedRelative = $RelativePath -replace '/', '\'
    $combinedPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($ProgramStoreRootPath, $normalizedRelative))

    if (-not $combinedPath.StartsWith($ProgramStoreRootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Store path escapes the program's store folder: $RelativePath"
    }

    $combinedPath
}

# Detect whether the process has administrative rights.
function Test-IsElevated {
    try {
        $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        throw "Failed to determine elevation state"
    }
}

# Ensure parent folder exists for a target path.
function Ensure-ParentDirectory {
    param([Parameter(Mandatory=$true)][string]$FilePath)

    $parentPath = Split-Path -Parent $FilePath
    if ([string]::IsNullOrWhiteSpace($parentPath)) {
        return
    }

    if (-not (Test-Path -LiteralPath $parentPath)) {
        New-Item -ItemType Directory -Path $parentPath -Force | Out-Null
    }
}

# Remove read-only attribute so overwrites succeed.
function Clear-ReadOnly {
    param([Parameter(Mandatory=$true)][string]$FilePath)

    if (-not (Test-Path -LiteralPath $FilePath)) {
        return
    }

    try {
        $attributes = [System.IO.File]::GetAttributes($FilePath)
        if (($attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
            [System.IO.File]::SetAttributes($FilePath, $attributes -bxor [System.IO.FileAttributes]::ReadOnly)
        }
    } catch {
        throw "Failed to clear read-only attribute"
    }
}

# Compare two files by size, modification time, and optionally by hash.
function Compare-Files {
    param(
        [Parameter(Mandatory=$true)][string]$FilePathA,
        [Parameter(Mandatory=$true)][string]$FilePathB,
        [switch]$UseHash
    )

    if (-not (Test-Path -LiteralPath $FilePathA) -or -not (Test-Path -LiteralPath $FilePathB)) {
        return $false
    }

    $fileA = Get-Item -LiteralPath $FilePathA -Force
    $fileB = Get-Item -LiteralPath $FilePathB -Force

    if ($fileA.Length -ne $fileB.Length) {
        return $false
    }

    # Without hash comparison, different timestamps indicate different files.
    if ($fileA.LastWriteTimeUtc -ne $fileB.LastWriteTimeUtc -and -not $UseHash) {
        return $false
    }

    if ($UseHash) {
        $hashA = Get-FileHash -LiteralPath $FilePathA -Algorithm SHA256
        $hashB = Get-FileHash -LiteralPath $FilePathB -Algorithm SHA256
        return $hashA.Hash -eq $hashB.Hash
    }

    return $true
}

# Copy a single file with skip and overwrite logic.
function Copy-File {
    param(
        [Parameter(Mandatory=$true)][string]$StorePath,
        [Parameter(Mandatory=$true)][string]$LivePath
    )

    if (-not (Test-Path -LiteralPath $StorePath)) {
        return [pscustomobject]@{
            Status  = $StatusCodes.Missing
            Store   = $StorePath
            Live    = $LivePath
            Message = 'Source not found'
        }
    }

    try {
        Ensure-ParentDirectory -FilePath $LivePath

        if (Test-Path -LiteralPath $LivePath) {
            if (Compare-Files -FilePathA $StorePath -FilePathB $LivePath) {
                return [pscustomobject]@{
                    Status  = $StatusCodes.Skipped
                    Store   = $StorePath
                    Live    = $LivePath
                    Message = 'Already identical'
                }
            }
            Clear-ReadOnly -FilePath $LivePath
        }

        Copy-Item -LiteralPath $StorePath -Destination $LivePath -Force

        [pscustomobject]@{
            Status  = $StatusCodes.Succeeded
            Store   = $StorePath
            Live    = $LivePath
            Message = $null
        }
    } catch {
        [pscustomobject]@{
            Status  = $StatusCodes.Failed
            Store   = $StorePath
            Live    = $LivePath
            Message = $_.Exception.Message
        }
    }
}

# Copy a directory tree with per-file decisions.
function Copy-Directory {
    param(
        [Parameter(Mandatory=$true)][string]$StorePath,
        [Parameter(Mandatory=$true)][string]$LivePath
    )

    if (-not (Test-Path -LiteralPath $StorePath)) {
        return [pscustomobject]@{
            Results = @([pscustomobject]@{
                Status  = $StatusCodes.Missing
                Store   = $StorePath
                Live    = $LivePath
                Message = 'Source folder not found'
            })
        }
    }

    $results = New-Object System.Collections.Generic.List[object]

    try {
        if (-not (Test-Path -LiteralPath $LivePath)) {
            New-Item -ItemType Directory -Path $LivePath -Force | Out-Null
        }

        Get-ChildItem -LiteralPath $StorePath -Recurse -File -ErrorAction Stop | ForEach-Object {
            $relativePath = $_.FullName.Substring($StorePath.Length).TrimStart('\','/')
            $liveFilePath = Join-Path $LivePath $relativePath
            $storeFilePath = $_.FullName

            $copyResult = Copy-File -StorePath $storeFilePath -LivePath $liveFilePath
            $results.Add($copyResult)
        }
    } catch {
        $results.Add([pscustomobject]@{
            Status  = $StatusCodes.Failed
            Store   = $StorePath
            Live    = $LivePath
            Message = $_.Exception.Message
        })
    }

    [pscustomobject]@{ Results = $results }
}

# Import a registry file using reg.exe.
function Import-RegFile {
    param([Parameter(Mandatory=$true)][string]$FilePath)

    if (-not (Test-Path -LiteralPath $FilePath)) {
        return [pscustomobject]@{
            Status  = $StatusCodes.Missing
            File    = $FilePath
            Message = 'File not found'
        }
    }

    if (-not ($FilePath.ToLowerInvariant().EndsWith('.reg'))) {
        return [pscustomobject]@{
            Status  = $StatusCodes.Failed
            File    = $FilePath
            Message = 'File must end with .reg'
        }
    }

    try {
        # Temporarily allow stderr output without throwing exceptions
        $savedErrorAction = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $output = & reg.exe import $FilePath 2>&1
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedErrorAction
        }

        if ($exitCode -eq 0) {
            [pscustomobject]@{
                Status  = $StatusCodes.Imported
                File    = $FilePath
                Message = $null
            }
        } else {
            # Extract actual error message from output
            $errorMessage = if ($output) {
                ($output | Where-Object { $_ -match 'ERROR:' -or $_ -is [System.Management.Automation.ErrorRecord] } |
                 ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ } } |
                 Select-Object -First 1)
            } else {
                'Registry import failed with exit code {0}' -f $exitCode
            }

            if (-not $errorMessage) {
                $errorMessage = 'Registry import failed with exit code {0}' -f $exitCode
            }

            [pscustomobject]@{
                Status  = $StatusCodes.Failed
                File    = $FilePath
                Message = $errorMessage
            }
        }
    } catch {
        [pscustomobject]@{
            Status  = $StatusCodes.Failed
            File    = $FilePath
            Message = $_.Exception.Message
        }
    }
}

# Write operation result to console with appropriate formatting.
function Write-OperationResult {
    param(
        [Parameter(Mandatory=$true)][psobject]$Result
    )

    switch ($Result.Status) {
        $StatusCodes.Succeeded {
            if (Test-HasProperty -Object $Result -PropertyName 'Live') {
                Write-Host ('Succeeded {0} -> {1}' -f $Result.Store, $Result.Live)
            } else {
                Write-Host ('Succeeded {0}' -f $Result.File)
            }
        }
        $StatusCodes.Skipped {
            if (Test-HasProperty -Object $Result -PropertyName 'Live') {
                Write-Host ('Skipped {0}' -f $Result.Live)
            } else {
                Write-Host ('Skipped {0}' -f $Result.File)
            }
        }
        $StatusCodes.Missing {
            if (Test-HasProperty -Object $Result -PropertyName 'Store') {
                Write-Host ('Missing {0}' -f $Result.Store)
            } else {
                Write-Host ('Missing {0}' -f $Result.File)
            }
        }
        $StatusCodes.Failed {
            $displayPath = if (Test-HasProperty -Object $Result -PropertyName 'Live') {
                $Result.Live
            } elseif (Test-HasProperty -Object $Result -PropertyName 'File') {
                $Result.File
            } elseif (Test-HasProperty -Object $Result -PropertyName 'Store') {
                $Result.Store
            } else {
                '<unknown>'
            }
            Write-Host ('Failed {0}: {1}' -f $displayPath, $Result.Message)
        }
        $StatusCodes.Imported {
            Write-Host ('Imported {0}' -f $Result.File)
        }
    }
}

# Update counter hashtable based on operation result.
function Update-Counters {
    param(
        [Parameter(Mandatory=$true)][psobject]$Result,
        [Parameter(Mandatory=$true)][hashtable]$Counters
    )

    switch ($Result.Status) {
        $StatusCodes.Succeeded { $Counters.Succeeded++ }
        $StatusCodes.Skipped   { $Counters.Skipped++ }
        $StatusCodes.Missing   { $Counters.Missing++ }
        $StatusCodes.Failed    { $Counters.Failed++ }
        $StatusCodes.Imported  { $Counters.Succeeded++ }
        default                { $Counters.Failed++ }
    }
}

# Handle an operation result by writing output and updating counters.
function Handle-OperationResult {
    param(
        [Parameter(Mandatory=$true)][psobject]$Result,
        [Parameter(Mandatory=$true)][hashtable]$Counters
    )

    Write-OperationResult -Result $Result
    Update-Counters -Result $Result -Counters $Counters
}

# Process file mappings for a program.
function Process-FileMapping {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext,
        [Parameter(Mandatory=$true)][hashtable]$Counters
    )

    $program = $ProgramContext.Spec

    if (-not (Test-HasProperty -Object $program -PropertyName 'files') -or -not $program.files) {
        return
    }

    foreach ($file in $program.files) {
        try {
            $storePath = Resolve-StorePath -ProgramStoreRootPath $ProgramContext.ProgramStoreRootPath -RelativePath $file.store
            $livePath = Normalize-Path (Expand-EnvTokens -Text $file.live)

            $result = Copy-File -StorePath $storePath -LivePath $livePath
            Handle-OperationResult -Result $result -Counters $Counters
        } catch {
            $result = [pscustomobject]@{
                Status  = $StatusCodes.Failed
                Store   = $file.store
                Live    = $file.live
                Message = $_.Exception.Message
            }
            Handle-OperationResult -Result $result -Counters $Counters
        }
    }
}

# Process directory mappings for a program.
function Process-DirectoryMapping {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext,
        [Parameter(Mandatory=$true)][hashtable]$Counters
    )

    $program = $ProgramContext.Spec

    if (-not (Test-HasProperty -Object $program -PropertyName 'directories') -or -not $program.directories) {
        return
    }

    foreach ($directory in $program.directories) {
        try {
            $storeDirPath = Resolve-StorePath -ProgramStoreRootPath $ProgramContext.ProgramStoreRootPath -RelativePath $directory.store
            $liveDirPath = Normalize-Path (Expand-EnvTokens -Text $directory.live)

            $directoryResult = Copy-Directory -StorePath $storeDirPath -LivePath $liveDirPath
            foreach ($result in $directoryResult.Results) {
                Handle-OperationResult -Result $result -Counters $Counters
            }
        } catch {
            $result = [pscustomobject]@{
                Status  = $StatusCodes.Failed
                Store   = $directory.store
                Live    = $directory.live
                Message = $_.Exception.Message
            }
            Handle-OperationResult -Result $result -Counters $Counters
        }
    }
}

# Process registry file imports for a program.
function Process-RegistryFiles {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext,
        [Parameter(Mandatory=$true)][hashtable]$Counters,
        [Parameter(Mandatory=$true)][bool]$IsElevated
    )

    $program = $ProgramContext.Spec

    if (-not (Test-HasProperty -Object $program -PropertyName 'registryFiles') -or -not $program.registryFiles) {
        return
    }

    foreach ($registryFile in $program.registryFiles) {
        try {
            $registryFilePath = Resolve-StorePath -ProgramStoreRootPath $ProgramContext.ProgramStoreRootPath -RelativePath $registryFile

            if (-not $IsElevated) {
                $result = [pscustomobject]@{
                    Status  = $StatusCodes.Skipped
                    File    = $registryFilePath
                    Message = 'Requires elevation'
                }
            } else {
                $result = Import-RegFile -FilePath $registryFilePath
            }

            Handle-OperationResult -Result $result -Counters $Counters
        } catch {
            $result = [pscustomobject]@{
                Status  = $StatusCodes.Failed
                File    = $registryFile
                Message = $_.Exception.Message
            }
            Handle-OperationResult -Result $result -Counters $Counters
        }
    }
}

# Display manual checklist items for a program.
function Show-ManualItems {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext
    )

    $program = $ProgramContext.Spec

    if (-not (Test-HasProperty -Object $program -PropertyName 'manual') -or -not $program.manual) {
        return
    }

    foreach ($manualItem in $program.manual) {
        Write-Host ('- {0}' -f $manualItem)
    }
}

# Restore a single program's configuration.
function Invoke-ProgramRestore {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext,
        [Parameter(Mandatory=$true)][bool]$IsElevated
    )

    $counters = @{
        Succeeded = 0
        Skipped   = 0
        Missing   = 0
        Failed    = 0
    }

    Write-Host ("`n{0}" -f $ProgramContext.Name)

    Process-FileMapping -ProgramContext $ProgramContext -Counters $counters
    Process-DirectoryMapping -ProgramContext $ProgramContext -Counters $counters
    Process-RegistryFiles -ProgramContext $ProgramContext -Counters $counters -IsElevated $IsElevated
    Show-ManualItems -ProgramContext $ProgramContext

    return $counters
}

# Prepare global tallies.
$Totals = @{
    Succeeded = 0
    Skipped   = 0
    Missing   = 0
    Failed    = 0
}

# Read and parse the map configuration.
$ConfigJson = Get-Content -LiteralPath $MapPath -Raw -Encoding UTF8
try {
    $Config = $ConfigJson | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "Map configuration could not be parsed"
}

# Validate store root.
if (-not (Test-HasProperty -Object $Config -PropertyName 'storeRoot')) {
    throw "Map configuration lacks a defined store root"
}
Test-NonEmptyString -Value $Config.storeRoot -PropertyName 'storeRoot' -Context 'Map configuration'

# Validate programs list exists.
if (-not (Test-HasProperty -Object $Config -PropertyName 'programs')) {
    throw "Map configuration is missing a list of program entries"
}
Test-IsList -Value $Config.programs -PropertyName 'programs' -Context 'Map configuration'

# Validate each program entry.
$Programs = @($Config.programs)
foreach ($program in $Programs) {
    Test-IsObject -Value $program -Context 'Program entry'
    Test-PropertyExists -Object $program -PropertyName 'name' -Context 'Program entry'
    Test-NonEmptyString -Value $program.name -PropertyName 'name' -Context 'Program entry'

    # Validate file mappings if present.
    if (Test-HasProperty -Object $program -PropertyName 'files') {
        Test-IsList -Value $program.files -PropertyName 'files' -Context 'Program entry'
        foreach ($file in $program.files) {
            Assert-MappingObject -Mapping $file -MappingType 'File'
        }
    }

    # Validate directory mappings if present.
    if (Test-HasProperty -Object $program -PropertyName 'directories') {
        Test-IsList -Value $program.directories -PropertyName 'directories' -Context 'Program entry'
        foreach ($directory in $program.directories) {
            Assert-MappingObject -Mapping $directory -MappingType 'Directory'
        }
    }

    # Validate manual checklist if present.
    if (Test-HasProperty -Object $program -PropertyName 'manual') {
        Test-IsList -Value $program.manual -PropertyName 'manual' -Context 'Program entry'
        foreach ($manualItem in $program.manual) {
            Test-NonEmptyString -Value $manualItem -PropertyName 'manual item' -Context 'Manual checklist'
        }
    }

    # Validate registry files if present.
    if (Test-HasProperty -Object $program -PropertyName 'registryFiles') {
        Test-IsList -Value $program.registryFiles -PropertyName 'registryFiles' -Context 'Program entry'
        foreach ($registryFile in $program.registryFiles) {
            Test-NonEmptyString -Value $registryFile -PropertyName 'registry file' -Context 'Registry file list'
            if (-not ($registryFile.ToString().ToLowerInvariant().EndsWith('.reg'))) {
                throw "Registry file entry must end with .reg"
            }
        }
    }
}

# Expand and normalize the store root.
$StoreRootPath = Normalize-Path (Expand-EnvTokens -Text ([string]$Config.storeRoot))

# Prepare program contexts with computed store folders.
$ProgramContexts = foreach ($program in $Programs) {
    $programStorePath = $program.name -replace '/', '\'
    $programStoreRootPath = [System.IO.Path]::Combine($StoreRootPath, $programStorePath)
    $programStoreRootPathFull = [System.IO.Path]::GetFullPath($programStoreRootPath)

    [pscustomobject]@{
        Spec                  = $program
        Name                  = $program.name
        ProgramStoreRootPath  = $programStoreRootPathFull
    }
}

# Cache elevation state for later decisions.
$IsElevated = Test-IsElevated

# Process each program entry.
foreach ($context in $ProgramContexts) {
    $programCounters = Invoke-ProgramRestore -ProgramContext $context -IsElevated $IsElevated

    $Totals.Succeeded += $programCounters.Succeeded
    $Totals.Skipped   += $programCounters.Skipped
    $Totals.Missing   += $programCounters.Missing
    $Totals.Failed    += $programCounters.Failed
}

# Print overall results.
Write-Host ("`nSucceeded={0}" -f $Totals.Succeeded)
Write-Host ("Skipped={0}"   -f $Totals.Skipped)
Write-Host ("Missing={0}"   -f $Totals.Missing)
Write-Host ("Failed={0}"    -f $Totals.Failed)

# Exit with appropriate status.
exit ([int](($Totals.Failed -gt 0) -or ($Totals.Missing -gt 0)))