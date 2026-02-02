## routes/download.py
"""
다운로드 라우트 모듈
파일 다운로드 기능 처리
"""
## routes/download.py
from flask import Blueprint, send_file, jsonify, request
import os
import json
import logging
from datetime import datetime

download_bp = Blueprint('download', __name__)

# 다운로드 통계 파일
DOWNLOAD_STATS_FILE = 'logs/download_stats.json'

def load_download_stats():
    """다운로드 통계 로드"""
    try:
        if os.path.exists(DOWNLOAD_STATS_FILE):
            with open(DOWNLOAD_STATS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"통계 로드 실패: {e}")
    return {}

def save_download_stats(stats):
    """다운로드 통계 저장"""
    try:
        with open(DOWNLOAD_STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
    except Exception as e:
        logging.error(f"통계 저장 실패: {e}")

def log_download(file_id, client_info):
    """다운로드 로그 기록"""
    stats = load_download_stats()
    
    if file_id not in stats:
        stats[file_id] = {
            'download_count': 0,
            'first_download': None,
            'last_download': None,
            'clients': []
        }
    
    current_time = datetime.now().isoformat()
    stats[file_id]['download_count'] += 1
    stats[file_id]['last_download'] = current_time
    
    if not stats[file_id]['first_download']:
        stats[file_id]['first_download'] = current_time
    
    # 클라이언트 정보 추가 (중복 제거)
    client_key = f"{client_info['ip']}_{client_info['user_agent'][:50]}"
    if client_key not in [c.get('key', '') for c in stats[file_id]['clients']]:
        stats[file_id]['clients'].append({
            'key': client_key,
            'ip': client_info['ip'],
            'user_agent': client_info['user_agent'],
            'timestamp': current_time
        })
    
    save_download_stats(stats)

@download_bp.route('/download/<file_id>')
def download_file(file_id):
    """파일 다운로드"""
    try:
        # 파일 경로 확인
        file_path = os.path.join('downloads', file_id)
        
        if not os.path.exists(file_path):
            return jsonify({'error': '파일을 찾을 수 없습니다'}), 404
        
        # 클라이언트 정보 수집
        client_info = {
            'ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent', ''),
            'referer': request.headers.get('Referer', ''),
            'timestamp': datetime.now().isoformat()
        }
        
        # 다운로드 로그 기록
        log_download(file_id, client_info)
        
        # 로그 출력
        logging.info(f"📥 다운로드: {file_id} from {client_info['ip']}")
        
        return send_file(file_path, as_attachment=True, download_name=file_id)
        
    except Exception as e:
        logging.error(f"다운로드 오류: {e}")
        return jsonify({'error': '다운로드 실패'}), 500

@download_bp.route('/api/download/stats/<file_id>')
def get_download_stats(file_id):
    """특정 파일의 다운로드 통계"""
    try:
        stats = load_download_stats()
        file_stats = stats.get(file_id, {
            'download_count': 0,
            'first_download': None,
            'last_download': None,
            'clients': []
        })
        
        return jsonify({
            'file_id': file_id,
            'stats': file_stats
        })
        
    except Exception as e:
        logging.error(f"통계 조회 오류: {e}")
        return jsonify({'error': '통계 조회 실패'}), 500