#
# Script to perform bit flipping on a valid signed EXE in order to find X number of copies with a new hash but with signature still intact/valid
#

# Param init
param (
	[Parameter(Mandatory=$false,Position=1)][string]$BinFile,
	[Parameter(Mandatory=$false,Position=2)][int]$BinCount,
	[Parameter(Mandatory=$false,Position=2)][int]$ByteOffset
	
)

# Param checks and help info
If ((!$BinFile) -or (!$BinCount)) {
	Write-Host "`nUsage:"
	Write-Host "     powershell.exe Get-BitFlippedBinary.ps1 -BinFile <file to process> -BinCount <num of valid bins to produce>"
	Write-Host " "
	Write-Host "Example:"
	Write-Host "     powershell.exe Get-BitFlippedBinary.ps1 -BinFile calc.exe -BinCount 20`n"
	Exit
}

# Check that you have a copy of signtool.exe - update path as needed
$signtoolPath = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\signtool.exe"
if (!(Test-Path $signtoolPath)) {
	Write-Host "[+] signtool.exe not found"
	Exit
}

# Function to check authenticode signature via signtool (pwsh cmdlet sucks, catalog vs file sigs)
function Check-CodeSignature {
param (
	[Parameter(Mandatory=$true,Position=1)][string]$file
)
	$file = (Get-item $file).FullName
	
	$pinfo = New-Object System.Diagnostics.ProcessStartInfo
	$pinfo.FileName = $signtoolPath
	$pinfo.RedirectStandardError = $true
	$pinfo.RedirectStandardOutput = $true
	$pinfo.UseShellExecute = $false
	$pinfo.Arguments = ("verify", $file)
	
	$p = New-Object System.Diagnostics.Process
	$p.StartInfo = $pinfo
	$p.Start() | Out-Null
	$p.WaitForExit()
	$stdout = $p.StandardOutput.ReadToEnd()
	$stderr = $p.StandardError.ReadToEnd()
	
	$output = $stdout + "`n" + $stderr
	
	if ($output -match "Successfully verified") {
		return $True
	} else {
		return $False
	}
}

# Function to get signature cert CN via signtool (pwsh cmdlet sucks, catalog vs file sigs)
function Get-CodeSigner {
param (
	[Parameter(Mandatory=$true,Position=1)][string]$file
)
	$output = & $signtoolPath verify /v $file
	$signer = $output -match "Issued to"
	$signer = $signer -replace "`tIssued to","`nIssued to"
	$signer = $signer -replace " Issued to","`nIssued to"
	$signer = $signer -replace "  "," "
	$signer = $signer + "`n"
	return $signer
}

# Check file exists
if (!(Test-Path $BinFile)) {
	Write-Host "[+] Binary file not found"
	Exit
}
Write-Host "[+] Processing file:" $BinFile

# Check file has a valid signature
$originalBinSignature = Check-CodeSignature $BinFile
if (!$originalBinSignature) {
	Write-Host "[+] Binary file does not have a valid signature"
	Exit
}
Write-Host "[+] Signature chain:`n" (Get-CodeSigner $BinFile)

# Get original file hash
$originalBinHash = (Get-FileHash -Algorithm SHA256 $BinFile).Hash
Write-Host "[+] Original SHA2 hash:" $originalBinHash "`n"

# Track number of new binaries with unique hash and intact/valid signature
$NewBins = 0

# Read file binary data
$BinBytes = Get-Content $BinFile -Encoding Byte

# Starting bit position at end of file
$CurrentByte = $BinBytes.Length - 1

# Optionally decrement by byte offset param
if ($ByteOffset) {
	$CurrentByte = $CurrentByte - $ByteOffset
}

# Work backwards through binary file data performing bit flipping
do {
	# Copy original bytes
	$NewBinBytes = $BinBytes
	
	# Flip current byte
	$NewBinBytes[$CurrentByte] = $NewBinBytes[$CurrentByte] -bxor "0XDE"
	
	# Decrement our byte position
	$CurrentByte -= 1
	
	# Write new bytes to file
	$NewBinFile = (pwd).Path + "\" + (Get-Item $BinFile).Name + "_" + $CurrentByte.ToString() + ".exe"
	[System.IO.File]::WriteAllBytes($NewBinFile, $NewBinBytes)
	
	# Check if new file has valid signature
	if ((Check-CodeSignature $NewBinFile)) {
		
		# Signature is valid
		Write-Host "[+] Binary file" $NewBinFile "has a valid signature"
		
		# Check if new file has a new hash
		$newBinHash = (Get-FileHash -Algorithm SHA256 $NewBinFile).Hash
		if ($originalBinHash -ne $newBinHash) {
			
			# Hash is new
			Write-Host "[+] Binary file" $NewBinFile "has a unique SHA2 hash:" $newBinHash "`n"
			
			# Increment our new bin counter
			$NewBins += 1
			
			# Continue to avoid deleting our valid bin
			Continue
		}
	}
	
	try {
		# Delete invalid bin
		Remove-Item $NewBinFile -Force -ErrorAction Stop 2>&1 | out-null
	}
	catch {
		# Retry as sometimes signtool handle is not released yet
		Wait 2 | Out-Null
		Remove-Item $NewBinFile -Force
	}
	
} while ($CurrentByte -gt 0 -and $NewBins -lt $BinCount)

# If file bytes exhausted
if ($CurrentByte -eq 0) {
	Write-Host "[+] Aborting, file bytes exhausted"
}

# If bin count reached
if ($NewBins -eq $BinCount) {
	Write-Host "[+] Aborting, bin count reached"
}

# Done
Write-Host "[+] Done!"
