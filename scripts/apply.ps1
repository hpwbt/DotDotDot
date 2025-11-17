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
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot  = Split-Path $ScriptDir -Parent
$MapPath   = Join-Path $RepoRoot "map.json"

$ExpectedStorePath = Join-Path $env:USERPROFILE 'Dotfiles'
if (-not (Test-Path -LiteralPath $ExpectedStorePath)) {
    Write-Host ("`nDotfiles directory not found at: {0}" -f $ExpectedStorePath) -ForegroundColor Yellow
    Write-Host "Rename current directory and move it to the expected path"
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
        [Parameter(Mandatory=$true)][string]$ProgramStoreRoot,
        [Parameter(Mandatory=$true)][string]$RelativePath
    )

    $normalizedRelative = $RelativePath -replace '/', '\'
    $combined = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($ProgramStoreRoot, $normalizedRelative))

    if (-not $combined.StartsWith($ProgramStoreRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Store path escapes the program's store folder: $RelativePath"
    }

    $combined
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
    param([Parameter(Mandatory=$true)][string]$Path)

    $parent = Split-Path -Parent $Path
    if ([string]::IsNullOrWhiteSpace($parent)) {
        return
    }

    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
}

# Remove read-only attribute so overwrites succeed.
function Clear-ReadOnly {
    param([Parameter(Mandatory=$true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    try {
        $attributes = [System.IO.File]::GetAttributes($Path)
        if (($attributes -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
            [System.IO.File]::SetAttributes($Path, $attributes -bxor [System.IO.FileAttributes]::ReadOnly)
        }
    } catch {
        throw "Failed to clear read-only attribute"
    }
}

# Compare two files by size, modification time, and optionally by hash.
function Compare-Files {
    param(
        [Parameter(Mandatory=$true)][string]$PathA,
        [Parameter(Mandatory=$true)][string]$PathB,
        [switch]$UseHash
    )

    if (-not (Test-Path -LiteralPath $PathA) -or -not (Test-Path -LiteralPath $PathB)) {
        return $false
    }

    $fileA = Get-Item -LiteralPath $PathA -Force
    $fileB = Get-Item -LiteralPath $PathB -Force

    if ($fileA.Length -ne $fileB.Length) {
        return $false
    }

    # Without hash comparison, different timestamps indicate different files.
    if ($fileA.LastWriteTimeUtc -ne $fileB.LastWriteTimeUtc -and -not $UseHash) {
        return $false
    }

    if ($UseHash) {
        $hashA = Get-FileHash -LiteralPath $PathA -Algorithm SHA256
        $hashB = Get-FileHash -LiteralPath $PathB -Algorithm SHA256
        return $hashA.Hash -eq $hashB.Hash
    }

    return $true
}

# Copy a single file with skip and overwrite logic.
function Copy-File {
    param(
        [Parameter(Mandatory=$true)][string]$Store,
        [Parameter(Mandatory=$true)][string]$Live
    )

    if (-not (Test-Path -LiteralPath $Store)) {
        return [pscustomobject]@{
            Status  = $StatusCodes.Missing
            Store   = $Store
            Live    = $Live
            Message = 'Source not found'
        }
    }

    try {
        Ensure-ParentDirectory -Path $Live

        if (Test-Path -LiteralPath $Live) {
            if (Compare-Files -PathA $Store -PathB $Live) {
                return [pscustomobject]@{
                    Status  = $StatusCodes.Skipped
                    Store   = $Store
                    Live    = $Live
                    Message = 'Already identical'
                }
            }
            Clear-ReadOnly -Path $Live
        }

        Copy-Item -LiteralPath $Store -Destination $Live -Force

        [pscustomobject]@{
            Status  = $StatusCodes.Succeeded
            Store   = $Store
            Live    = $Live
            Message = $null
        }
    } catch {
        [pscustomobject]@{
            Status  = $StatusCodes.Failed
            Store   = $Store
            Live    = $Live
            Message = $_.Exception.Message
        }
    }
}

# Copy a directory tree with per-file decisions.
function Copy-Directory {
    param(
        [Parameter(Mandatory=$true)][string]$Store,
        [Parameter(Mandatory=$true)][string]$Live
    )

    if (-not (Test-Path -LiteralPath $Store)) {
        return [pscustomobject]@{
            Results = @([pscustomobject]@{
                Status  = $StatusCodes.Missing
                Store   = $Store
                Live    = $Live
                Message = 'Source folder not found'
            })
        }
    }

    $results = New-Object System.Collections.Generic.List[object]

    try {
        if (-not (Test-Path -LiteralPath $Live)) {
            New-Item -ItemType Directory -Path $Live -Force | Out-Null
        }

        Get-ChildItem -LiteralPath $Store -Recurse -File -ErrorAction Stop | ForEach-Object {
            $relativePath = $_.FullName.Substring($Store.Length).TrimStart('\','/')
            $liveFile = Join-Path $Live $relativePath
            $storeFile = $_.FullName

            $copyResult = Copy-File -Store $storeFile -Live $liveFile
            $results.Add($copyResult)
        }
    } catch {
        $results.Add([pscustomobject]@{
            Status  = $StatusCodes.Failed
            Store   = $Store
            Live    = $Live
            Message = $_.Exception.Message
        })
    }

    [pscustomobject]@{ Results = $results }
}

# Import a registry file using reg.exe.
function Import-RegFile {
    param([Parameter(Mandatory=$true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{
            Status  = $StatusCodes.Missing
            File    = $Path
            Message = 'File not found'
        }
    }

    if (-not ($Path.ToLowerInvariant().EndsWith('.reg'))) {
        return [pscustomobject]@{
            Status  = $StatusCodes.Failed
            File    = $Path
            Message = 'File must end with .reg'
        }
    }

    try {
        $process = Start-Process -FilePath 'reg.exe' `
                                  -ArgumentList "import `"$Path`"" `
                                  -NoNewWindow `
                                  -Wait `
                                  -PassThru

        if ($process.ExitCode -eq 0) {
            [pscustomobject]@{
                Status  = $StatusCodes.Imported
                File    = $Path
                Message = $null
            }
        } else {
            [pscustomobject]@{
                Status  = $StatusCodes.Failed
                File    = $Path
                Message = 'Exit code {0}' -f $process.ExitCode
            }
        }
    } catch {
        [pscustomobject]@{
            Status  = $StatusCodes.Failed
            File    = $Path
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
        default {
            $displayPath = if (Test-HasProperty -Object $Result -PropertyName 'Live') {
                $Result.Live
            } elseif (Test-HasProperty -Object $Result -PropertyName 'File') {
                $Result.File
            } elseif (Test-HasProperty -Object $Result -PropertyName 'Store') {
                $Result.Store
            } else {
                '<unknown>'
            }
            Write-Host ('Failed {0}: Unknown status ''{1}''' -f $displayPath, $Result.Status)
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
            $storePath = Resolve-StorePath -ProgramStoreRoot $ProgramContext.ProgramStoreRoot -RelativePath $file.store
            $livePath = Normalize-Path (Expand-EnvTokens -Text $file.live)

            if (-not (Test-Path -LiteralPath $storePath)) {
                $result = [pscustomobject]@{
                    Status  = $StatusCodes.Missing
                    Store   = $storePath
                    Live    = $null
                    Message = 'Source not found'
                }
                Handle-OperationResult -Result $result -Counters $Counters
                continue
            }

            $result = Copy-File -Store $storePath -Live $livePath
            Handle-OperationResult -Result $result -Counters $Counters
        } catch {
            $result = [pscustomobject]@{
                Status  = $StatusCodes.Failed
                Store   = $file.live
                Live    = $null
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
            $storeDirectory = Resolve-StorePath -ProgramStoreRoot $ProgramContext.ProgramStoreRoot -RelativePath $directory.store
            $liveDirectory = Normalize-Path (Expand-EnvTokens -Text $directory.live)

            if (-not (Test-Path -LiteralPath $storeDirectory)) {
                $result = [pscustomobject]@{
                    Status  = $StatusCodes.Missing
                    Store   = $storeDirectory
                    Live    = $null
                    Message = 'Source folder not found'
                }
                Handle-OperationResult -Result $result -Counters $Counters
                continue
            }

            $directoryResult = Copy-Directory -Store $storeDirectory -Live $liveDirectory
            foreach ($result in $directoryResult.Results) {
                Handle-OperationResult -Result $result -Counters $Counters
            }
        } catch {
            $result = [pscustomobject]@{
                Status  = $StatusCodes.Failed
                Store   = $directory.live
                Live    = $null
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

    if (-not $IsElevated) {
        # Skip all registry imports if not elevated.
        foreach ($registryFile in $program.registryFiles) {
            try {
                $registryPath = Resolve-StorePath -ProgramStoreRoot $ProgramContext.ProgramStoreRoot -RelativePath $registryFile
                $result = [pscustomobject]@{
                    Status  = $StatusCodes.Skipped
                    File    = $registryPath
                    Message = 'Requires elevation'
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
    } else {
        # Process registry imports when elevated.
        foreach ($registryFile in $program.registryFiles) {
            try {
                $registryPath = Resolve-StorePath -ProgramStoreRoot $ProgramContext.ProgramStoreRoot -RelativePath $registryFile
                $result = Import-RegFile -Path $registryPath
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

    Write-Host ('Summary: succeeded={0} skipped={1} missing={2} failed={3}' -f
                $counters.Succeeded, $counters.Skipped, $counters.Missing, $counters.Failed)

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
$StoreRoot = Normalize-Path (Expand-EnvTokens -Text ([string]$Config.storeRoot))

# Prepare program contexts with computed store folders.
$ProgramContexts = foreach ($program in $Programs) {
    $programStorePath = $program.name -replace '/', '\'
    $programStoreRoot = [System.IO.Path]::Combine($StoreRoot, $programStorePath)
    $programStoreRootFull = [System.IO.Path]::GetFullPath($programStoreRoot)

    [pscustomobject]@{
        Spec             = $program
        Name             = $program.name
        ProgramStoreRoot = $programStoreRootFull
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
exit ([int]($Totals.Failed -gt 0))