# BadShares

```PowerShell
  (          (     )\ )    )                      
( )\     )   )\ ) (()/( ( /(     )  (      (      
)((_) ( /(  (()/(  /(_)))\()) ( /(  )(    ))\ (   
((_)_  )(_))  ((_))(_)) ((_)\  )(_))(()\  /((_))\
| _ )((_)_   _| | / __|| |(_)((_)_  ((_)(_)) ((_)
| _ \/ _` |/ _` | \__ \| ' \ / _` || '_|/ -_)(_-<
|___/\__,_|\__,_| |___/|_||_|\__,_||_|  \___|/__/

By: Spencer Alessi                          v0.1 
```
A tool to create randomly insecure file shares that also contain unsecured credential files.

## Setup

1. Clone the repo then dot source the script

```PowerShell
git clone https://github.com/techspence/BadShares
cd BadShares
. .\Invoke-BadShares
```

2. Open PowerShell and download `Invoke-BadShares.ps1` manually

```PowerShell 
# You may need to explicitly set the TLS version on older Windows like Server 2016
# [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest https://raw.githubusercontent.com/techspence/BadShares/main/Invoke-BadShares.ps1 -OutFile Invoke-BadShares.ps1
. .\Invoke-BadShares
```

## Usage

There are two options for creating BadShares.

1. Run BadShares with default settings

```PowerShell
Invoke-BadShares
```

2. Run BadShares and provide custom settings

```PowerShell
$BadSharesArray = @("IT","Accounting","Marketing","Executives","HR")
Invoke-BadShares -Root "C:\MyStuff" -Name "BadShares" -BadShareList $BadSharesArray
```

## How It Works

When you run BadShares, it will attempt to:

1. Create a root folder for all the BadShares it creates (e.g c:\BadShares)
2. Create various subfolders under the BadShares root folder (e.g. IT, Accounting, etc.)
3. Intentionally set insecure permissions on random shared folders (e.g. Everyone with FullControl)
4. Create random unsecured credentials files and scatter them in random shares folders (e.g. password.doc in the Accounting share)

A couple other things to note: When you run BadShares it will attempt to clear out any pre-existing shares & files from the BadShares root.

The script will also prompt you at each step, just to make sure you want to continue allowing the script to do it's thing.

## Default Settings

|Setting|Value(s)|
|-------|--------|
|BadShares root folder|c:\ |
|BadShares folder name|BadShares|
|Share Names|"Human Resources","Finance","Marketing" "Sales","Information Technology","Customer Service","Research and Development","Operations","Legal","Administration","Public Relations","Quality Assurance","Supply Chain Management","Product Management","Training and Development","Accounting","Business Development","Engineering","Design","Logistics","Purchasing","Risk Management","Compliance","Facilities Management","Health and Safety","Internal Audit","Corporate Communications"|
|Random File Names|"Annual Report","Quarterly Review","Marketing Plan","Sales Presentation","Financial Statement","Budget Forecast","Invoice 2024","Contract Agreement","Employment Contract","Resume John Doe","Cover Letter","Meeting Minutes 2024 04 01","Policy Guidelines","Procedure Manual","Project Plan Phase1","Product Catalog","Client Proposal","Employee Handbook","Expense Report","Training Materials","Feedback Survey","Database Backup","Error Log","Marketing Campaign","Training Schedule","Performance Review","Customer List","Service Level Agreement","Vendor Contract","Meeting Agenda 2024 04 05","Product Specifications","Purchase Order","Sales Forecast","Project Status Report","Expense Budget 2024","Marketing Strategy","Customer Satisfaction Survey","Training Manual","Feedback Form","Vendor List","Security Policy","Employee Handbook Updates","Performance Appraisal Form","IT Support Request","Risk Assessment","Change Request Form","Weekly Timesheet","Customer Service Policy","Product Demo Video"|
|Random File Extensions|".txt", ".doc", ".docx", ".pdf", ".xlsx", ".xls", ".pptx", ".ppt", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".zip", ".7z", ".rar", ".csv", ".xml", ".html", ".css", ".json", ".mp3", ".mp4", ".avi", ".mov", ".wav", ".tiff", ".psd", ".svg"|
|Random Credential Files|"password.txt", "pwd.txt", "login.txt", "unattend.xml", "web.cofig", "install.ini", "passwords.doc", "passwords.docx", "passwords.xls", "passwords.xlsx", "logins.doc", "logins.docx", "logins.xls", "logins.xlsx", "install.ps1", "ProdBackup.psm1", "ProdBackup.psd1", "adminsetup.vbs", "admin.bat", "setup.cmd"|
|Random Credentials|"Username: johndoe,Password: Password123", "Username: alice_smith,Password: qwerty456", "Username: admin_user,Password: P@ssw0rd!", "Username: user123,Password: SecretPass789", "Username: test_account,Password: LetMeIn2024", "Username: jane_doe,Password: Welcome123", "Username: developer_user,Password: DevPass@2024", "Username: support_user,Password: SupportPass#2024", "Username: marketing_user,Password: Market123!", "Username: operations_user,Password: OpsPass567","P@ssw0rd123!", "SecurePass456$", "RandomPass789*", "Str0ngPassword!", "Pa\$\$w0rd!123", "Secur3P@ss", "P@ssw0rd2024", "StrongP@ssword!", "Pa\$\$w0rd!456", "RandomP@ss789", "password", "123456", "qwerty", "abc123", "letmein", "password1", "12345678", "welcome", "admin", "iloveyou", "1234567", "football", "123123", "monkey", "1234567890", "1234", "123456789", "dragon", "baseball", "sunshine"|
