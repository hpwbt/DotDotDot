Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Display cleanup message.
Write-Host "`nINFO: " -ForegroundColor Cyan -NoNewline
Write-Host "Uninstalling programs . . ."

# Define programs to uninstall.
$ProgramsToUninstall = @(
    'Microsoft.OneDrive',
    'MSIX\Clipchamp.Clipchamp_4.4.10420.0_x64__yxz26nhyzhsrt',
    'Microsoft.Teams',
    'MSIX\Microsoft.ApplicationCompatibilityEnhancements_1.2401.10.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.BingNews_1.0.2.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.BingSearch_1.1.37.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.BingWeather_4.54.63029.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.Edge.GameAssist_1.0.3590.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.GamingApp_2511.1001.12.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.GetHelp_10.2409.32612.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.MicrosoftOfficeHub_19.2511.46031.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.MicrosoftSolitaireCollection_4.24.11040.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.OutlookForWindows_1.0.0.0_neutral__8wekyb3d8bbwe',
    'MSIX\Microsoft.Paint_11.2509.441.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.PowerAutomateDesktop_1.0.2029.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.Services.Store.Engagement_10.0.23012.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.Services.Store.Engagement_10.0.23012.0_x86__8wekyb3d8bbwe',
    'MSIX\Microsoft.StartExperiencesApp_1.168.2.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.StorePurchaseApp_22509.1401.1.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.Todos_0.148.3611.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.WidgetsPlatformRuntime_1.6.14.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.Windows.DevHome_0.1700.597.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.Windows.Photos_2025.11100.9001.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.WindowsAlarms_1.1.61.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.WindowsCalculator_11.2508.1.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.WindowsCamera_2025.2505.2.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.WindowsFeedbackHub_1.2510.14102.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.WindowsNotepad_11.2508.38.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.WindowsSoundRecorder_1.1.5.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.Xbox.TCUI_1.24.10001.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.XboxGamingOverlay_7.325.7221.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.XboxIdentityProvider_12.110.15002.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.XboxSpeechToTextOverlay_1.111.30001.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.YourPhone_0.25102.64.0_x64__8wekyb3d8bbwe',
    'MSIX\Microsoft.ZuneMusic_11.2501.9.0_x64__8wekyb3d8bbwe',
    'MSIX\MicrosoftCorporationII.QuickAssist_2.0.35.0_x64__8wekyb3d8bbwe',
    'MSIX\MicrosoftWindows.Client.WebExperience_525.31002.150.0_x64__cw5n1h2txyewy',
    'MSIX\MicrosoftWindows.CrossDevice_0.25101.31.0_x64__cw5n1h2txyewy',
    'MSIX\Microsoft.MicrosoftStickyNotes_4.0.6105.0_x64__8wekyb3d8bbwe'
)

# Uninstall each program.
foreach ($programId in $ProgramsToUninstall) {
    try {
        # Run winget uninstall with silent flag and suppress msstore errors.
        & winget uninstall --id $programId --silent --accept-source-agreements --source winget 2>$null
    } catch {
        # Best effort - continue on any error.
    }
}

exit 0