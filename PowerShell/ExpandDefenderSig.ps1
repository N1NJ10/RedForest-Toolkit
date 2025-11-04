filter Expand-DefenderAVSignatureDB {
<#
.SYNOPSIS

Decompresses a Windows Defender AV signature database (.VDM file).

.DESCRIPTION

Expand-DefenderAVSignatureDB extracts a Windows Defender AV signature database (.VDM file). This function was developed by reversing mpengine.dll and with the help of Tavis Ormandy and his LoadLibrary project (https://github.com/taviso/loadlibrary). Note: Currently, "scrambled" databases are not supported although, I have yet to encounter a scrambled database. Thus far, all databases I've encountered are zlib-compressed.

.PARAMETER FilePath

Specifies the path to a Defender AV signature file. Defender AV signature databases are stored in "%ProgramData%\Microsoft\Windows Defender\Definition Updates\{GUID}\*.vdm". The file path must have the .vdm extension.

.PARAMETER OutputFileName

Specifies the filename of the extracted signature database. This is written to the current working directory.

.EXAMPLE

ls 'C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{42F61A44-8142-4AF4-8E13-6EA18B60C397}\mpavbase.vdm' | Expand-DefenderAVSignatureDB -OutputFileName mpavbase.decompressed

Extracts the signature database from mpavbase.vdm and writes it to mpavbase.decompressed in the current directory.

.OUTPUTS

System.IO.FileInfo

Outputs a FileInfo object indicating successful extraction of the .VDM file.
#>

    [OutputType([System.IO.FileInfo])]
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [String]
        [Alias('FullName')]
        [ValidateScript({$_.EndsWith('.vdm')})]
        $FilePath,

        [Parameter(Mandatory)]
        [String]
        [ValidateNotNullOrEmpty()]
        $OutputFileName
    )

    if (-not (Test-Path -Path $FilePath)) {
        Write-Error "$FilePath does not exist"
        return
    }

    $FileFullPath = Resolve-Path -Path $FilePath

    $FileBytes = [IO.File]::ReadAllBytes($FileFullPath.Path)

    if ([Text.Encoding]::ASCII.GetString($FileBytes[0..1]) -ne 'MZ') {
        Write-Error "$FileFullPath is not a valid PE file."
        return
    }

    # Note: Codepage 28591 returns a 1-to-1 char to byte mapping
    $Encoding = [Text.Encoding]::GetEncoding(28591)

    $FileString = $Encoding.GetString($FileBytes)

    # Most of this logic is present in mpengine!load_database and subsequent function calls

    $DatabaseSigRegex = [Regex] 'RMDX'

    $Result = $DatabaseSigRegex.Match($FileString)

    if (-not $Result.Success) {
        Write-Error 'Defender AV signature database header signature ("RMDX") was not found'
        return
    }

    $HeaderIndex = $Result.Index
    $HeaderSize = 0x40

    [Byte[]] $HeaderBytes = $FileBytes[$HeaderIndex..($HeaderIndex + $HeaderSize - 1)]

    $Options = [BitConverter]::ToInt32($HeaderBytes, 0x0C)
    $MaybeChecksum = [BitConverter]::ToInt32($HeaderBytes, 0x1C)
    $LastFieldUnknown = [BitConverter]::ToInt32($HeaderBytes, 0x3C)

    $IsCompressed = [Bool][Byte](($Options -shr 1) -band 0xFF)

    if (-not $IsCompressed) {
        Write-Warning 'Signature database is "scrambled". Figure out how to programmatically recover this. Unable to continue.'
        return
    }

    # Offset to the compressed data info from the start of the sig db header
    $CompressedDataInfoOffset = [BitConverter]::ToInt32($HeaderBytes, 0x18)

    if ((($Options -band 0x200000) -eq 0) -or ($MaybeChecksum -eq 0) -or ($LastFieldUnknown -eq 0)) {
        Write-Error "Invalid Defender AV signature database header."
        return
    }

    $CompressedDataLength = [BitConverter]::ToInt32($FileBytes, $HeaderIndex + $CompressedDataInfoOffset)
    $CompressedDataChecksumMaybe = [BitConverter]::ToInt32($FileBytes, $HeaderIndex + $CompressedDataInfoOffset + 4)
    $CompressedDataIndex = $HeaderIndex + $CompressedDataInfoOffset + 8

    # To-do: this is slow. I need to figure out how to speed up array splicing
    $CompressedData = $FileBytes[$CompressedDataIndex..($CompressedDataIndex + $CompressedDataLength - 1)]

    $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$CompressedData)

    # Write the decompressed signature database contents to the filename specified in the current directory.
    $DecompressedFileStream = [IO.File]::Create("$PWD\$OutputFileName")

    $DeflateStream = New-Object IO.Compression.DeflateStream -ArgumentList ($MemoryStream, [IO.Compression.CompressionMode]::Decompress)

    try {
        $DeflateStream.CopyTo($DecompressedFileStream)
    } catch {
        Write-Error $_
    } finally {
        $DeflateStream.Close()
        $DecompressedFileStream.Close()
        $MemoryStream.Close()
    }

    Get-Item -Path "$PWD\$OutputFileName"
}
