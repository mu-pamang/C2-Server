## routes/upload.py
"""
업로드 라우트 모듈
파일 업로드 및 명령 처리
"""

from flask import Blueprint, request, jsonify, render_template_string
import os
import json
import logging
import hashlib
from datetime import datetime
from werkzeug.utils import secure_filename

upload_bp = Blueprint('upload', __name__)

# 업로드 로그 파일
UPLOAD_LOG_FILE = 'logs/upload_log.json'

def load_upload_log():
    """업로드 로그 로드"""
    try:
        if os.path.exists(UPLOAD_LOG_FILE):
            with open(UPLOAD_LOG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"업로드 로그 로드 실패: {e}")
    return []

def save_upload_log(log_data):
    """업로드 로그 저장"""
    try:
        with open(UPLOAD_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error(f"업로드 로그 저장 실패: {e}")

def generate_file_id(filename, content=None):
    """파일 ID 생성"""
    timestamp = str(datetime.now().timestamp())
    if content:
        hash_input = f"{filename}_{timestamp}_{len(content)}"
    else:
        hash_input = f"{filename}_{timestamp}"
    
    return hashlib.md5(hash_input.encode()).hexdigest()[:12]

@upload_bp.route('/upload', methods=['GET', 'POST'])
def upload_endpoint():
    """업로드 엔드포인트"""
    
    if request.method == 'GET':
        # 업로드 폼 표시
        upload_form = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>📤 파일 업로드</title>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial; margin: 40px; background: #f5f5f5; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
                .form-group { margin: 20px 0; }
                label { display: block; margin-bottom: 5px; font-weight: bold; }
                input, textarea, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
                button { background: #007bff; color: white; padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; }
                button:hover { background: #0056b3; }
                .info { background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h2>📤 파일 업로드</h2>
                
                <div class="info">
                    <strong>업로드 방법:</strong><br>
                    • 파일 선택 후 업로드<br>
                    • 텍스트 직접 입력<br>
                    • 명령 실행 결과 업로드
                </div>
                
                <form method="POST" enctype="multipart/form-data">
                    <div class="form-group">
                        <label>📁 파일 업로드:</label>
                        <input type="file" name="file">
                    </div>
                    
                    <div class="form-group">
                        <label>📝 텍스트 데이터:</label>
                        <textarea name="text_data" rows="6" placeholder="텍스트를 직접 입력하세요..."></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>💻 명령 실행:</label>
                        <input type="text" name="command" placeholder="예: ls -la, whoami, pwd">
                    </div>
                    
                    <div class="form-group">
                        <label>🔖 파일명 (선택사항):</label>
                        <input type="text" name="custom_filename" placeholder="사용자 정의 파일명">
                    </div>
                    
                    <button type="submit">📤 업로드</button>
                </form>
                
                <div style="margin-top: 30px;">
                    <a href="/">← 관리 페이지로 돌아가기</a>
                </div>
            </div>
        </body>
        </html>
        """
        return upload_form
    
    elif request.method == 'POST':
        try:
            # 디버깅 로그 추가
            logging.info(f"POST /upload 요청 수신 - Form data: {dict(request.form)}")
            logging.info(f"Files: {list(request.files.keys())}")
            
            file_content = None
            filename = None
            upload_type = None
            
            # 1. 파일 업로드 처리
            if 'file' in request.files and request.files['file'].filename:
                file = request.files['file']
                filename = secure_filename(file.filename)
                file_content = file.read()
                upload_type = 'file'
                logging.info(f"파일 업로드 처리: {filename}")
                
            # 2. 텍스트 데이터 처리
            elif request.form.get('text_data'):
                text_data = request.form.get('text_data')
                filename = request.form.get('custom_filename', 'text_data.txt')
                file_content = text_data.encode('utf-8')
                upload_type = 'text'
                logging.info(f"텍스트 데이터 처리: {filename}, 크기: {len(file_content)}")
                
            # 3. 명령 실행 처리
            elif request.form.get('command'):
                import subprocess
                command = request.form.get('command')
                logging.info(f"명령 실행: {command}")
                
                try:
                    result = subprocess.run(
                        command, 
                        shell=True, 
                        capture_output=True, 
                        text=True, 
                        timeout=30
                    )
                    
                    output = f"Command: {command}\n"
                    output += f"Exit Code: {result.returncode}\n"
                    output += f"STDOUT:\n{result.stdout}\n"
                    if result.stderr:
                        output += f"STDERR:\n{result.stderr}\n"
                    
                    filename = request.form.get('custom_filename', f'command_output.txt')
                    file_content = output.encode('utf-8')
                    upload_type = 'command'
                    
                except subprocess.TimeoutExpired:
                    logging.error("명령 실행 시간 초과")
                    return jsonify({'error': '명령 실행 시간 초과'}), 400
                except Exception as e:
                    logging.error(f"명령 실행 실패: {e}")
                    return jsonify({'error': f'명령 실행 실패: {str(e)}'}), 400
            
            else:
                logging.error("업로드할 데이터가 없음")
                return jsonify({'error': '업로드할 데이터가 없습니다'}), 400
            
            # 파일 ID 생성
            file_id = generate_file_id(filename, file_content)
            
            # 파일 저장
            save_path = os.path.join('uploads', file_id)
            with open(save_path, 'wb') as f:
                f.write(file_content)
            
            # 로그 기록
            client_info = {
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', ''),
                'timestamp': datetime.now().isoformat()
            }
            
            upload_log = load_upload_log()
            upload_log.append({
                'file_id': file_id,
                'original_filename': filename,
                'file_size': len(file_content),
                'upload_type': upload_type,
                'client_info': client_info
            })
            
            # 최근 100개만 유지
            upload_log = upload_log[-100:]
            save_upload_log(upload_log)
            
            logging.info(f"📤 업로드: {filename} ({upload_type}) -> {file_id}")
            
            return jsonify({
                'success': True,
                'file_id': file_id,
                'filename': filename,
                'size': len(file_content),
                'type': upload_type,
                'message': '업로드 성공!'
            })
            
        except Exception as e:
            logging.error(f"업로드 오류: {e}")
            return jsonify({'error': f'업로드 실패: {str(e)}'}), 500

@upload_bp.route('/api/upload/list')
def list_uploads():
    """업로드된 파일 목록"""
    try:
        upload_log = load_upload_log()
        return jsonify({
            'uploads': upload_log[-20:],  # 최근 20개
            'total': len(upload_log)
        })
    except Exception as e:
        logging.error(f"업로드 목록 조회 오류: {e}")
        return jsonify({'error': '목록 조회 실패'}), 500