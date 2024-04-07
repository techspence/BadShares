function New-BadSharesRootDirectory {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$Root = "C:\",

        [ValidateNotNullOrEmpty()]
        [string]$Name = "BadShares"
    )

    begin {
        $BadSharesRoot = $Root
        $BadSharesSharesDirectoryName = "BadShares"
        $BadSharesPath = "$BadSharesRoot$BadSharesSharesDirectoryName"
    }

    process {
        Write-Host "If you continue, this script create several new folders and files." -ForegroundColor Yellow 
        Write-Host "Do you want to continue [Y] Yes "  -ForegroundColor Yellow -NoNewline
        Write-Host "[N] " -ForegroundColor Yellow -NoNewline
        Write-Host "No: "  -ForegroundColor Yellow -NoNewline
        $WarningError = ''
        $WarningError = Read-Host
        if ($WarningError -like 'y') {
            Write-Host "`n[i] Beginning the BadShares setup process..."
           
        } else {
            Write-Host "`n[!] Guess you're starting over?.." -ForegroundColor Yellow
            break;
        }
        if (Test-Path -Path $BadSharesPath) {
            Write-Warning "[!] The directory '$BadSharesPath' already exists!"
            Write-Host "[i] If you continue, this script will overwrite: " -ForegroundColor Yellow -NoNewline
            Write-Host "$BadSharesPath" -ForegroundColor Cyan
            Write-Host "[i] Do you want to continue [Y] Yes "  -ForegroundColor Yellow -NoNewline
            Write-Host "[N] " -ForegroundColor Yellow -NoNewline
            Write-Host "No: "  -ForegroundColor Yellow -NoNewline
            $WarningError = ''
            $WarningError = Read-Host
            if ($WarningError -like 'y') {
                Write-Host "`n[i] Creating a shares directory at: $BadSharesPath"
                try {
                    New-Item -Path $BadSharesPath -ItemType Directory -Force
                } catch {
                    Write-Error "Could not create the directory '$BadSharesPath'. Please check the path and run again."
                }
            } else {
                Write-Host "`n[i] You chose to NOT create a share directory.`n[i] Create the shares directory manually or run again to create the shares directory." -ForegroundColor Yellow
                break;
            }
        } else {
            Write-Host "[i] Creating a shares directory at: $BadSharesPath"
            try {
                New-Item -Path $BadSharesPath -ItemType Directory
            } catch {
                Write-Error "Could not create the directory '$BadSharesPath'. Please check the path and run again."
                break;
            }
        }

        if (Test-Path -Path $BadSharesPath) {
            Write-Host "[i] The shares directory '$BadSharesPath' has been created."
        } else {
            Write-Error "Could not create the directory '$BadSharesPath'. Please check the path and run again."
            break;
        }
    }
}

function New-SMBSharedFolder {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$Root = "C:\BadShares",

        [ValidateNotNullOrEmpty()]
        [string[]]$BadShareNames
    )

    Write-Warning "[i] Now we will create the SMB Shares"
    Write-Host "[i] If you continue, this script will create SMB shares for each BadShare: " -ForegroundColor Yellow
    Write-Host "[i] Do you want to continue [Y] Yes "  -ForegroundColor Yellow -NoNewline
    Write-Host "[N] " -ForegroundColor Yellow -NoNewline
    Write-Host "No: "  -ForegroundColor Yellow -NoNewline
    $WarningError = ''
    $WarningError = Read-Host
    if ($WarningError -like 'y') {
        Write-Host "`n[i] Creating new SMB shares"
        try {
            New-Item -Path $BadSharesPath -ItemType Directory -Force
        } catch {
            Write-Error "Could not create SMB shares."
        }
    } else {
        Write-Host "`n[i] You chose to NOT create a the SMB shares.`n[i] Create the shares manually or run again to create the shares." -ForegroundColor Yellow
        break;
    }

    foreach ($Name in $BadShareNames) {
        $BadSharePath = "$Root\$Name"
        Write-Verbose "Creating directory: $BadSharePath"
        try {
            New-Item -Path $BadSharePath -ItemType Directory
        } catch {
            Write-Error "Could not create BadShare: BadSharePath"
        }

        try {
            New-SmbShare -Name $Name -Path $BadSharePath
        } catch {
            Write-Error "Could not create the SMB Share for $BadSharePath"
        }
    }

    Write-Host "[i] Finished creating BadShares"
}

function Clear-BadShares {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$Root = "C:\BadShares"
    )
    $SharedFolders = Get-ChildItem -Path $Root

    foreach ($Share in $SharedFolders) {
        Remove-SmbShare -Name $Share.Name
    }
    Remove-Item -Path $Root -Recurse #-Confirm
}

function New-RandomLastWriteTime {
    [CmdletBinding()]
    param (
        [string]$filePath
    )

    if (-not (Test-Path $filePath)) {
        Write-Error "File '$filePath' does not exist."
        return
    }

    $randomDays = Get-Random -Minimum 0 -Maximum 7300
    $timeSpan = New-TimeSpan -Days $randomDays

    $currentLastWriteTime = (Get-Item $filePath).LastWriteTime

    if ($currentLastWriteTime.Add($timeSpan) -gt (Get-Date)){
        Write-Verbose "Trying to set the time to: $($currentLastWriteTime.Add($timeSpan)). Time traveler huh?"
        $newLastWriteTime = $currentLastWriteTime.Add(-$timeSpan)
        Set-ItemProperty -Path $filePath -Name LastWriteTime -Value $newLastWriteTime
    } elseif ($currentLastWriteTime.Add($timeSpan) -lt ((Get-Date).AddYears(-20))) {
        Write-Verbose "Trying to set the time to: $($currentLastWriteTime.Add($timeSpan)). How old are you?"
        $newLastWriteTime = $currentLastWriteTime.AddYears(20)
        Set-ItemProperty -Path $filePath -Name LastWriteTime -Value $newLastWriteTime
    } else {
        $newLastWriteTime = $currentLastWriteTime.Add($timeSpan)
        Set-ItemProperty -Path $filePath -Name LastWriteTime -Value $newLastWriteTime
    }

    Write-Verbose "Last write time of '$filePath' has been randomly changed to: $newLastWriteTime" 
}

function New-RandomFile {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $FileNames = @("Annual Report","Quarterly Review","Marketing Plan","Sales Presentation",
                   "Financial Statement","Budget Forecast","Invoice 2024","Contract Agreement",
                   "Employment Contract","Resume John Doe","Cover Letter","Meeting Minutes 2024 04 01",
                   "Policy Guidelines","Procedure Manual","Project Plan Phase1","Product Catalog",
                   "Client Proposal","Employee Handbook","Expense Report","Training Materials",
                   "Feedback Survey","Database Backup","Error Log","Marketing Campaign","Training Schedule",
                   "Performance Review","Customer List","Service Level Agreement","Vendor Contract",
                   "Meeting Agenda 2024 04 05","Product Specifications","Purchase Order","Sales Forecast",
                   "Project Status Report","Expense Budget 2024","Marketing Strategy","Customer Satisfaction Survey",
                   "Training Manual","Feedback Form","Vendor List","Security Policy","Employee Handbook Updates",
                   "Performance Appraisal Form","IT Support Request","Risk Assessment","Change Request Form",
                   "Weekly Timesheet","Customer Service Policy","Product Demo Video")
    $RandomFileName = $FileNames | Get-Random
    $FileExtensions = @(".txt",".doc",".docx",".pdf",".xlsx",".xls",".pptx",".ppt",".jpg",".jpeg",
                        ".png",".gif",".bmp",".zip",".7z",".rar",".csv",".xml",".html",".css",
                        ".json",".mp3",".mp4",".avi",".mov",".wav",".tiff",".psd",".svg")
    $RandomFileExtension = $FileExtensions | Get-Random
    $RandomFullFileName = "$Path\$RandomFileName$RandomFileExtension"
    $RandomFileSize = Get-Random -Minimum 1 -Maximum 25000

    fsutil file createnew $RandomFullFileName $RandomFileSize | Out-Null
    New-RandomLastWriteTime -filePath $RandomFullFileName
    New-RandomLastWriteTime -filePath $Path
}

function Add-DummyFiles {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [int]$NumberOfDummyFiles = 10,
        
        [ValidateNotNullOrEmpty()]
        [string]$Root = "C:\BadShares"
    )

    $BadSharesRoot = $Root
    $BadSharesFolders = Get-ChildItem -Path $BadSharesRoot

    foreach ($Share in $BadSharesFolders) {
        1..$NumberOfDummyFiles | ForEach-Object {
            New-RandomFile -Path $Share.FullName 
        }
    }
}

function Test-IsElevated {
    <#
    .SYNOPSIS
        Tests if PowerShell is running with elevated privileges (run as Administrator).
    .DESCRIPTION
        This function returns True if the script is being run as an administrator or False if not.
    .EXAMPLE
        Test-IsElevated
    .EXAMPLE
        if (!(Test-IsElevated)) { Write-Host "You are not running with elevated privileges and will not be able to make any changes." -ForeGroundColor Yellow }
    .EXAMPLE
        # Prompt to launch elevated if not already running as administrator:
        if (!(Test-IsElevated)) {
            $arguments = "& '" + $myinvocation.mycommand.definition + "'"
            Start-Process powershell -Verb runAs -ArgumentList $arguments
            Break
        }
    #>
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Set-MiconfiguredBadShares {
    [CmdletBinding()]
    param (
        [object]$ShareList
    )

    $Groups = @("Everyone", "$($env:USERDOMAIN)\Domain Users", "NT AUTHORITY\Authenticated Users", "NT AUTHORITY\ANONYMOUS LOGON")
    $UnsafePermissions = @("FullControl","Write","Modify")

    1..10 | ForEach-Object {
        $RandomSharedFolder = $ShareList | Get-Random 
        $RandomGroup = $Groups | Get-Random
        $RandomUnsafePermission = $UnsafePermissions | Get-Random
        $RandomShare = Get-Item $RandomSharedFolder.FullName
        $RandomFileACL = (Get-Item $RandomShare).GetAccessControl()
        $RandomFileArgs = $RandomGroup, $RandomUnsafePermission, "Allow"
        $RandomFileAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $RandomFileArgs
        $RandomFileACL.SetAccessRule($RandomFileAccessRule)
        $RandomShare.SetAccessControl($RandomFileACL)
    }
}

function Set-UnsecuredCredentials {
    [CmdletBinding()]
    param (
        [object]$ShareList
    )

    $FileNames = @("password.txt","pwd.txt","login.txt","unattend.xml","web.cofig",
                   "install.ini","passwords.doc","passwords.docx","passwords.xls",
                   "passwords.xlsx","logins.doc","logins.docx","logins.xls","logins.xlsx",
                   "install.ps1","ProdBackup.psm1", "ProdBackup.psd1", "adminsetup.vbs", 
                   "admin.bat", "setup.cmd")
    $UnsecredCredentials = @("Username: user123
                              Password: SecretPass789",
                             "Username: test_account
                             Password: LetMeIn2024")
    foreach ($Share in $ShareList.FullName) {
        $RandomFileName = $FileNames | Get-Random
        New-Item -Path $Share -Name $RandomFileName -Value $($UnsecredCredentials | Get-Random)
    }
}

function Find-BadShares {
    [CmdletBinding()]
    param (
        [String[]]$ShareList
    )
    foreach ($Share in $ShareList) {
        #Write-Host "Checking permissions on $Share"
        #$SharedFolder = Get-Item $Share
        $Access = (Get-Acl $Share).Access | Where-Object {$_.IdentityReference -match "Domain Users|Authenticated Users|Everyone" -and $_.FileSystemRights -Match "FullControl|Write|Modify" }
        foreach ($Ace in $Access) {
            $ShareObject = [pscustomobject]@{
                SharePath = $Share
                Identity = $Ace.IdentityReference
                Permissions = $Ace.FileSystemRights
                Type = $Ace.AccessControlType
            }
        }
        $ShareObject
    }
}

function Find-UnsecuredCredentials {
    [CmdletBinding()]
    param (
        [String[]]$ShareList
    )
    $Shares = Get-ChildItem $ShareList -Recurse -File
    foreach ($Share in $Shares) {
        if ($Share.BaseName -Match "password|pwd|login|admin|install|web|unattend|backup|setup"){
            $ShareObject = [pscustomobject]@{
                SharePath = $Share.FullName
                Keyword = $Matches[0]
            }
        }
        $ShareObject
    }
}

function Invoke-BadShares {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string]$Root = "C:\",

        [ValidateNotNullOrEmpty()]
        [string]$Name = "BadShares",

        [ValidateNotNullOrEmpty()]
        [string[]]$BadShareList = @("Human Resources","Finance","Marketing","Sales","Information Technology",
        "Customer Service","Research and Development","Operations","Legal","Administration","Public Relations",
        "Quality Assurance","Supply Chain Management","Product Management","Training and Development","Accounting",
        "Business Development","Engineering","Design","Logistics","Purchasing","Risk Management","Compliance",
        "Facilities Management","Health and Safety","Internal Audit","Corporate Communications")
    )

    if (Test-IsElevated) {
        # Continue
    } else {
        Write-Warning -Message "Creating SMB Shares requirs Administrator rights. Please launch an elevated PowerShell session."
        break;
    }

function Get-Art {
    Write-Host "                   (                               " -ForegroundColor Red
    Write-Host "   (          (     )\ )    )                      " -ForegroundColor Red
    Write-Host " ( )\     )   )\ ) (()/( ( /(     )  (      (      " -ForegroundColor Red
    Write-Host " )((_) ( /(  (()/(  /(_)))\()) ( /(  )(    ))\ (   " -ForegroundColor Yellow
    Write-Host "((_)_  )(_))  ((_))(_)) ((_)\  )(_))(()\  /((_))\  " -ForegroundColor DarkYellow
    Write-Host " | _ )((_)_   _| | / __|| |(_)((_)_  ((_)(_)) ((_) " -ForegroundColor Cyan
    Write-Host " | _ \/ _`` |/ _`` | \__ \| ' \ / _`` || '_|/ -_)(_-< " -ForegroundColor Cyan
    Write-Host " |___/\__,_|\__,_| |___/|_||_|\__,_||_|  \___|/__/ " -ForegroundColor Cyan

    Write-Host "`n By: Spencer Alessi                          v0.1 "
}
    Get-Art
    Write-Host "`nWelcome to BadShares`n" -BackgroundColor White -ForegroundColor Red
    Write-Host "BadShares creates file shares with random names and randomly misconfigured permissions."
    Write-Host "It also creates unsecured credential files and scatters them randomly throughout the shares.`n"
    Write-Warning "DO NOT RUN IN PRODUCTION!"
    Write-Host "`nRun " -NoNewline 
    Write-Host "Clear-BadShares" -ForegroundColor Cyan -NoNewLine
    Write-Host " to remove all BadShares.`n"


    # create a BadShare folders, where all our bad shares will live
    $BadShareRoot = New-BadSharesRootDirectory

    # create SMB shares from our BadShares
    $BadShareFolders = New-SMBSharedFolder -Root $BadShareRoot.FullName -BadShareNames $BadShareList

    # fill our BadShares with dummy data
    Add-DummyFiles -NumberOfDummyFiles 5 -Root $BadShareRoot.FullName
    
    # intentionally misconfigure some of our BadShares
    $BadShares = Get-ChildItem $BadShareRoot -Directory
    Set-MiconfiguredBadShares -ShareList $BadShares

    # fill our BadShares with credential material such as:
    # password files: .txt, .doc(x), .xls(x), unattend.xml
    # config files: web.config, .config, .ini, .xml
    # certificates: .pfx
    # scripts: .ps1, .psm1, .psd1, .vbs, .bat, .cmd
    $RandomBadShares = $BadShares | Get-Random -Count 10
    $UnsecuredCredentials = Set-UnsecuredCredentials -ShareList $RandomBadShares

    Find-BadShares -ShareList $BadShares.FullName | ft -AutoSize
    Find-UnsecuredCredentials -ShareList $BadShares.FullName | Sort-Object -Unique -Property SharePath
}