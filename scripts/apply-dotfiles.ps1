Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Status code constants.
$StatusCodes = @{
    Succeeded = 'succeeded'
    Skipped   = 'skipped'
    Missing   = 'missing'
    Failed    = 'failed'
    Imported  = 'imported'
}

# Resolve paths from script location.
$ScriptDirPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$DotfilesRootPath = Split-Path $ScriptDirPath -Parent
$StoreRootPath = Join-Path $DotfilesRootPath 'store'
$MapPath = Join-Path $DotfilesRootPath 'map.json'

# Verify we're running from inside %USERPROFILE%\Dotfiles.
$ExpectedDirPath = Join-Path $env:USERPROFILE 'Dotfiles'
if ($DotfilesRootPath -ne $ExpectedDirPath) {
    Write-Host "`nERROR: " -ForegroundColor Red -NoNewline
    Write-Host ("This script must be run from inside '{0}'." -f $ExpectedDirPath)
    Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
    Write-Host ("Current location: {0}." -f $DotfilesRootPath)
    Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
    Write-Host ("Expected location: {0}." -f $ExpectedDirPath)
    exit 1
}

# Verify the configuration file exists.
if (-not (Test-Path -LiteralPath $MapPath)) {
    throw "ERROR: Map configuration file not found at: $MapPath."
}

# Check if an object has a specific property.
function Test-HasProperty {
    param(
        [Parameter(Mandatory=$true)]$Object,
        [Parameter(Mandatory=$true)][string]$PropertyName
    )
    $null -ne $Object.PSObject.Properties[$PropertyName]
}

# Check if property exists and has a truthy value.
function Test-PropertyPopulated {
    param(
        [Parameter(Mandatory=$true)]$Object,
        [Parameter(Mandatory=$true)][string]$PropertyName
    )
    (Test-HasProperty -Object $Object -PropertyName $PropertyName) -and $Object.$PropertyName
}

# Validate that an object has a required property.
function Test-PropertyExists {
    param(
        [Parameter(Mandatory=$true)]$Object,
        [Parameter(Mandatory=$true)][string]$PropertyName,
        [Parameter(Mandatory=$true)][string]$Context
    )
    if (-not (Test-HasProperty -Object $Object -PropertyName $PropertyName)) {
        throw "ERROR: $Context lacks a $PropertyName."
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
        throw "ERROR: $Context $PropertyName must be a non-empty text value."
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
        throw "ERROR: $Context $PropertyName must be provided as a list."
    }
}

# Validate that a value is an object.
function Test-IsObject {
    param(
        [Parameter(Mandatory=$true)]$Value,
        [Parameter(Mandatory=$true)][string]$Context
    )
    if ($Value -isnot [PSCustomObject] -and $Value -isnot [hashtable]) {
        throw "ERROR: $Context must be an object."
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

# Validate a list property with custom item validation.
function Assert-ListProperty {
    param(
        [Parameter(Mandatory=$true)]$Object,
        [Parameter(Mandatory=$true)][string]$PropertyName,
        [Parameter(Mandatory=$true)][string]$Context,
        [Parameter(Mandatory=$true)][scriptblock]$ItemValidator
    )

    if (-not (Test-PropertyPopulated -Object $Object -PropertyName $PropertyName)) {
        return
    }

    Test-IsList -Value $Object.$PropertyName -PropertyName $PropertyName -Context $Context
    foreach ($item in $Object.$PropertyName) {
        & $ItemValidator $item
    }
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
            # Return a marker indicating undefined variable instead of throwing.
            return "__UNDEFINED_ENV_VAR__{0}__" -f $variableName
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

# Resolve a path inside the program's base folder and block path traversal.
function Resolve-StorePath {
    param(
        [Parameter(Mandatory=$true)][string]$ProgramBasePath,
        [Parameter(Mandatory=$true)][string]$RelativePath
    )

    $normalizedRelative = $RelativePath -replace '/', '\'
    $combinedPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($ProgramBasePath, $normalizedRelative))

    if (-not $combinedPath.StartsWith($ProgramBasePath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "ERROR: Store path escapes the program's store folder: $RelativePath."
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
        throw "ERROR: Failed to determine elevation state."
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
        throw "ERROR: Failed to clear read-only attribute."
    }
}

# Compare two files by size, modification time, and optionally by hash.
function Compare-Files {
    param(
        [Parameter(Mandatory=$true)][string]$SourceFilePath,
        [Parameter(Mandatory=$true)][string]$TargetFilePath,
        [switch]$UseHash
    )

    if (-not (Test-Path -LiteralPath $SourceFilePath) -or -not (Test-Path -LiteralPath $TargetFilePath)) {
        return $false
    }

    $sourceFile = Get-Item -LiteralPath $SourceFilePath -Force
    $targetFile = Get-Item -LiteralPath $TargetFilePath -Force

    if ($sourceFile.Length -ne $targetFile.Length) {
        return $false
    }

    # Without hash comparison, different timestamps indicate different files.
    if ($sourceFile.LastWriteTimeUtc -ne $targetFile.LastWriteTimeUtc -and -not $UseHash) {
        return $false
    }

    if ($UseHash) {
        $hashSource = Get-FileHash -LiteralPath $SourceFilePath -Algorithm SHA256
        $hashTarget = Get-FileHash -LiteralPath $TargetFilePath -Algorithm SHA256
        return $hashSource.Hash -eq $hashTarget.Hash
    }

    return $true
}

# Copy a single file with skip and overwrite logic.
function Copy-File {
    param(
        [Parameter(Mandatory=$true)][string]$StorePath,
        [Parameter(Mandatory=$true)][string]$LivePath
    )

    # Check if live path contains undefined environment variable marker.
    if ($LivePath -like '*__UNDEFINED_ENV_VAR__*') {
        $undefinedVar = if ($LivePath -match '__UNDEFINED_ENV_VAR__([A-Za-z0-9_]+)__') { $matches[1] } else { 'unknown' }
        return [pscustomobject]@{
            Status  = $StatusCodes.Skipped
            Store   = $StorePath
            Live    = $LivePath
            Message = "Environment variable `${0} not set." -f $undefinedVar
        }
    }

    if (-not (Test-Path -LiteralPath $StorePath)) {
        return [pscustomobject]@{
            Status  = $StatusCodes.Missing
            Store   = $StorePath
            Live    = $LivePath
            Message = 'Source not found.'
        }
    }

    try {
        Ensure-ParentDirectory -FilePath $LivePath

        if (Test-Path -LiteralPath $LivePath) {
            if (Compare-Files -SourceFilePath $StorePath -TargetFilePath $LivePath) {
                return [pscustomobject]@{
                    Status  = $StatusCodes.Skipped
                    Store   = $StorePath
                    Live    = $LivePath
                    Message = 'Already identical.'
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

    # Check if live path contains undefined environment variable marker.
    if ($LivePath -like '*__UNDEFINED_ENV_VAR__*') {
        $undefinedVar = if ($LivePath -match '__UNDEFINED_ENV_VAR__([A-Za-z0-9_]+)__') { $matches[1] } else { 'unknown' }
        return [pscustomobject]@{
            Results = @([pscustomobject]@{
                Status  = $StatusCodes.Skipped
                Store   = $StorePath
                Live    = $LivePath
                Message = "Environment variable `${0} not set." -f $undefinedVar
            })
        }
    }

    if (-not (Test-Path -LiteralPath $StorePath)) {
        return [pscustomobject]@{
            Results = @([pscustomobject]@{
                Status  = $StatusCodes.Missing
                Store   = $StorePath
                Live    = $LivePath
                Message = 'Source folder not found.'
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
            Message = 'File not found.'
        }
    }

    if (-not ($FilePath.ToLowerInvariant().EndsWith('.reg'))) {
        return [pscustomobject]@{
            Status  = $StatusCodes.Failed
            File    = $FilePath
            Message = 'File must end with .reg.'
        }
    }

    try {
        # Temporarily allow stderr output without throwing exceptions.
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
            # Extract actual error message from output.
            $errorMessage = if ($output) {
                ($output | Where-Object { $_ -match 'ERROR:' -or $_ -is [System.Management.Automation.ErrorRecord] } |
                 ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.Exception.Message } else { $_ } } |
                 Select-Object -First 1)
            } else {
                'Registry import failed with exit code {0}.' -f $exitCode
            }

            if (-not $errorMessage) {
                $errorMessage = 'Registry import failed with exit code {0}.' -f $exitCode
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
                Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
                Write-Host ('{0} -> {1}.' -f $Result.Store, $Result.Live)
            } else {
                Write-Host "SUCCESS: " -ForegroundColor Green -NoNewline
                Write-Host ('{0}.' -f $Result.File)
            }
        }
        $StatusCodes.Skipped {
            if (Test-HasProperty -Object $Result -PropertyName 'Live') {
                Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
                if ($Result.Message) {
                    Write-Host ('Skipped {0}. {1}' -f $Result.Live, $Result.Message)
                } else {
                    Write-Host ('Skipped {0}.' -f $Result.Live)
                }
            } else {
                Write-Host "WARNING: " -ForegroundColor Yellow -NoNewline
                if ($Result.Message) {
                    Write-Host ('Skipped {0}. {1}' -f $Result.File, $Result.Message)
                } else {
                    Write-Host ('Skipped {0}.' -f $Result.File)
                }
            }
        }
        $StatusCodes.Missing {
            if (Test-HasProperty -Object $Result -PropertyName 'Store') {
                Write-Host "ERROR: " -ForegroundColor Red -NoNewline
                Write-Host ('Missing {0}.' -f $Result.Store)
            } else {
                Write-Host "ERROR: " -ForegroundColor Red -NoNewline
                Write-Host ('Missing {0}.' -f $Result.File)
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
            Write-Host "ERROR: " -ForegroundColor Red -NoNewline
            Write-Host ('Failed {0}: {1}.' -f $displayPath, $Result.Message)
        }
        $StatusCodes.Imported {
            Write-Host "IMPORTED: " -ForegroundColor Cyan -NoNewline
            Write-Host ('{0}.' -f $Result.File)
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
        $StatusCodes.Imported  { $Counters.Imported++ }
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

# Process items from a property with error handling per item.
function Invoke-ItemProcessor {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext,
        [Parameter(Mandatory=$true)][hashtable]$Counters,
        [Parameter(Mandatory=$true)][string]$PropertyName,
        [Parameter(Mandatory=$true)][scriptblock]$ItemProcessor
    )

    $programDefinition = $ProgramContext.Definition

    if (-not (Test-PropertyPopulated -Object $programDefinition -PropertyName $PropertyName)) {
        return
    }

    foreach ($item in $programDefinition.$PropertyName) {
        try {
            $results = @(& $ItemProcessor $item $ProgramContext)
            foreach ($result in $results) {
                Handle-OperationResult -Result $result -Counters $Counters
            }
        } catch {
            $errorResult = [pscustomobject]@{
                Status  = $StatusCodes.Failed
                Message = $_.Exception.Message
            }

            # Add contextual properties based on item type.
            if ($item -is [PSCustomObject] -or $item -is [hashtable]) {
                if (Test-HasProperty -Object $item -PropertyName 'store') {
                    $errorResult | Add-Member -NotePropertyName 'Store' -NotePropertyValue $item.store
                }
                if (Test-HasProperty -Object $item -PropertyName 'live') {
                    $errorResult | Add-Member -NotePropertyName 'Live' -NotePropertyValue $item.live
                }
            } else {
                # Assume it's a file path string.
                $errorResult | Add-Member -NotePropertyName 'File' -NotePropertyValue $item
            }

            Handle-OperationResult -Result $errorResult -Counters $Counters
        }
    }
}

# Process file mappings for a program.
function Process-FileMapping {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext,
        [Parameter(Mandatory=$true)][hashtable]$Counters
    )

    Invoke-ItemProcessor -ProgramContext $ProgramContext -Counters $Counters -PropertyName 'files' -ItemProcessor {
        param($file, $context)
        $storePath = Resolve-StorePath -ProgramBasePath $context.ProgramBasePath -RelativePath $file.store
        $livePath = Normalize-Path (Expand-EnvTokens -Text $file.live)
        Copy-File -StorePath $storePath -LivePath $livePath
    }
}

# Process directory mappings for a program.
function Process-DirectoryMapping {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext,
        [Parameter(Mandatory=$true)][hashtable]$Counters
    )

    Invoke-ItemProcessor -ProgramContext $ProgramContext -Counters $Counters -PropertyName 'directories' -ItemProcessor {
        param($directory, $context)
        $storeDirPath = Resolve-StorePath -ProgramBasePath $context.ProgramBasePath -RelativePath $directory.store
        $liveDirPath = Normalize-Path (Expand-EnvTokens -Text $directory.live)
        $directoryResult = Copy-Directory -StorePath $storeDirPath -LivePath $liveDirPath

        # Return all individual file results.
        $directoryResult.Results
    }
}

# Process registry file imports for a program.
function Process-RegistryFiles {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext,
        [Parameter(Mandatory=$true)][hashtable]$Counters,
        [Parameter(Mandatory=$true)][bool]$HasAdminRights
    )

    Invoke-ItemProcessor -ProgramContext $ProgramContext -Counters $Counters -PropertyName 'registryFiles' -ItemProcessor {
        param($registryFile, $context)
        $registryFilePath = Resolve-StorePath -ProgramBasePath $context.ProgramBasePath -RelativePath $registryFile

        if (-not $HasAdminRights) {
            [pscustomobject]@{
                Status  = $StatusCodes.Skipped
                File    = $registryFilePath
                Message = 'Requires elevation.'
            }
        } else {
            Import-RegFile -FilePath $registryFilePath
        }
    }
}

# Display manual checklist items for a program.
function Show-ManualItems {
    param([Parameter(Mandatory=$true)][psobject]$ProgramContext)

    $programDefinition = $ProgramContext.Definition

    if (-not (Test-PropertyPopulated -Object $programDefinition -PropertyName 'manual')) {
        return
    }

    foreach ($manualItem in $programDefinition.manual) {
        Write-Host "MANUAL APPLY NEEDED FOR: " -ForegroundColor Magenta -NoNewline
        Write-Host $manualItem
    }
}

# Restore a single program's configuration.
function Invoke-ProgramRestore {
    param(
        [Parameter(Mandatory=$true)][psobject]$ProgramContext,
        [Parameter(Mandatory=$true)][bool]$HasAdminRights
    )

    $programCounters = @{
        Succeeded = 0
        Skipped   = 0
        Missing   = 0
        Failed    = 0
        Imported  = 0
    }

    Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
    Write-Host ("Processing {0}." -f $ProgramContext.Name)

    Process-FileMapping -ProgramContext $ProgramContext -Counters $programCounters
    Process-DirectoryMapping -ProgramContext $ProgramContext -Counters $programCounters
    Process-RegistryFiles -ProgramContext $ProgramContext -Counters $programCounters -HasAdminRights $HasAdminRights
    Show-ManualItems -ProgramContext $ProgramContext

    return $programCounters
}

# Prepare global tallies.
$OverallCounters = @{
    Succeeded = 0
    Skipped   = 0
    Missing   = 0
    Failed    = 0
    Imported  = 0
}

# Read and parse the map configuration.
$ConfigText = Get-Content -LiteralPath $MapPath -Raw -Encoding UTF8
try {
    $Config = $ConfigText | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "ERROR: Map configuration could not be parsed."
}

# Validate programs list exists.
if (-not (Test-HasProperty -Object $Config -PropertyName 'programs')) {
    throw "ERROR: Map configuration is missing a list of program entries."
}
Test-IsList -Value $Config.programs -PropertyName 'programs' -Context 'Map configuration'

# Validate each program entry.
$ProgramDefinitions = @($Config.programs)
foreach ($programDef in $ProgramDefinitions) {
    Test-IsObject -Value $programDef -Context 'Program entry'
    Test-PropertyExists -Object $programDef -PropertyName 'name' -Context 'Program entry'
    Test-NonEmptyString -Value $programDef.name -PropertyName 'name' -Context 'Program entry'

    # Validate file mappings if present.
    Assert-ListProperty -Object $programDef -PropertyName 'files' -Context 'Program entry' -ItemValidator {
        param($file)
        Assert-MappingObject -Mapping $file -MappingType 'File'
    }

    # Validate directory mappings if present.
    Assert-ListProperty -Object $programDef -PropertyName 'directories' -Context 'Program entry' -ItemValidator {
        param($directory)
        Assert-MappingObject -Mapping $directory -MappingType 'Directory'
    }

    # Validate manual checklist if present.
    Assert-ListProperty -Object $programDef -PropertyName 'manual' -Context 'Program entry' -ItemValidator {
        param($manualItem)
        Test-NonEmptyString -Value $manualItem -PropertyName 'manual item' -Context 'Manual checklist'
    }

    # Validate registry files if present.
    Assert-ListProperty -Object $programDef -PropertyName 'registryFiles' -Context 'Program entry' -ItemValidator {
        param($registryFile)
        Test-NonEmptyString -Value $registryFile -PropertyName 'registry file' -Context 'Registry file list'
        if (-not ($registryFile.ToString().ToLowerInvariant().EndsWith('.reg'))) {
            throw "ERROR: Registry file entry must end with .reg."
        }
    }
}

# Prepare program contexts with computed base paths.
$ProgramContexts = foreach ($programDef in $ProgramDefinitions) {
    $programSubdirName = $programDef.name -replace '/', '\'
    $programBasePath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($StoreRootPath, $programSubdirName))

    [pscustomobject]@{
        Definition      = $programDef
        Name            = $programDef.name
        ProgramBasePath = $programBasePath
    }
}

# Cache elevation state for later decisions.
$HasAdminRights = Test-IsElevated

# Process each program entry.
foreach ($programContext in $ProgramContexts) {
    $programCounters = Invoke-ProgramRestore -ProgramContext $programContext -HasAdminRights $HasAdminRights

    $OverallCounters.Succeeded += $programCounters.Succeeded
    $OverallCounters.Skipped   += $programCounters.Skipped
    $OverallCounters.Missing   += $programCounters.Missing
    $OverallCounters.Failed    += $programCounters.Failed
    $OverallCounters.Imported  += $programCounters.Imported
}

# Print overall results.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host ("Succeeded-{0}." -f $OverallCounters.Succeeded)
Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
Write-Host ("Skipped-{0}." -f $OverallCounters.Skipped)
Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
Write-Host ("Missing-{0}." -f $OverallCounters.Missing)
Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
Write-Host ("Failed-{0}." -f $OverallCounters.Failed)
Write-Host "INFO: " -ForegroundColor Cyan -NoNewline
Write-Host ("Imported-{0}." -f $OverallCounters.Imported)

# Exit with appropriate status.
exit ([int](($OverallCounters.Failed -gt 0) -or ($OverallCounters.Missing -gt 0)))