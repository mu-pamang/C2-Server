## routes/admin.py (API Only Version)
"""
관리 라우트 모듈 - API 전용 (프론트엔드 제거)
침해사고 대응 연습용 백엔드 API만 제공
"""

from flask import Blueprint, jsonify
import os
import json
import logging
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

def get_system_info():
    """시스템 정보 수집"""
    try:
        import psutil
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent
            },
            'disk': {
                'total': psutil.disk_usage('/').total,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent
            }
        }
    except Exception:
        return None

def format_bytes(bytes_value):
    """바이트를 읽기 쉬운 형태로 변환"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"

# 프론트엔드 대시보드 제거 - 대신 API 정보만 제공
@admin_bp.route('/')
def admin_api_info():
    """관리자 API 정보 (대시보드 제거)"""
    return jsonify({
        'message': 'C2 Server Management API',
        'version': '2.0-api-only',
        'description': 'Forensics exercise - Backend API only',
        'available_apis': {
            'system_info': '/api/system/info',
            'file_stats': '/api/files/stats', 
            'recent_logs': '/api/logs/recent',
            'victim_data': '/api/victims',
            'malware_data': {
                'beacons': '/api/beacons',
                'commands': '/api/commands',
                'exfiltrations': '/api/exfiltrations'
            }
        },
        'note': 'Frontend dashboard removed for forensics exercise'
    })

# API 엔드포인트들 (기존 유지)
@admin_bp.route('/api/system/info')
def get_system_info_api():
    """시스템 정보 API"""
    try:
        system_info = get_system_info()
        return jsonify({
            'system': system_info,
            'timestamp': datetime.now().isoformat(),
            'server_status': 'online'
        })
    except Exception as e:
        logging.error(f"시스템 정보 조회 오류: {e}")
        return jsonify({'error': '시스템 정보 조회 실패'}), 500

@admin_bp.route('/api/files/stats')
def get_file_stats_api():
    """파일 통계 API"""
    try:
        stats = {
            'uploads_count': 0,
            'downloads_count': 0,
            'total_upload_size': 0,
            'total_download_size': 0,
            'exfil_files': 0,
            'exfil_size': 0
        }
        
        # 업로드 파일 통계
        uploads_dir = 'uploads'
        if os.path.exists(uploads_dir):
            for filename in os.listdir(uploads_dir):
                filepath = os.path.join(uploads_dir, filename)
                if os.path.isfile(filepath):
                    stats['uploads_count'] += 1
                    stats['total_upload_size'] += os.path.getsize(filepath)
        
        # 유출 파일 통계  
        exfil_dir = 'uploads/exfil'
        if os.path.exists(exfil_dir):
            for filename in os.listdir(exfil_dir):
                filepath = os.path.join(exfil_dir, filename)
                if os.path.isfile(filepath):
                    stats['exfil_files'] += 1
                    stats['exfil_size'] += os.path.getsize(filepath)
        
        # 다운로드 파일 통계
        downloads_dir = 'downloads'
        if os.path.exists(downloads_dir):
            for filename in os.listdir(downloads_dir):
                filepath = os.path.join(downloads_dir, filename)
                if os.path.isfile(filepath):
                    stats['downloads_count'] += 1
                    stats['total_download_size'] += os.path.getsize(filepath)
        
        # 포맷팅된 크기 추가
        stats['formatted'] = {
            'total_upload_size': format_bytes(stats['total_upload_size']),
            'total_download_size': format_bytes(stats['total_download_size']),
            'exfil_size': format_bytes(stats['exfil_size'])
        }
                    
        return jsonify(stats)
    except Exception as e:
        logging.error(f"파일 통계 조회 오류: {e}")
        return jsonify({'error': '파일 통계 조회 실패'}), 500

@admin_bp.route('/api/logs/recent')
def get_recent_logs():
    """최근 로그 API"""
    try:
        logs = []
        log_file = 'logs/server.log'
        
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                logs = [line.strip() for line in lines[-50:] if line.strip()]
        
        return jsonify({
            'logs': logs,
            'total_lines': len(logs),
            'log_file': log_file
        })
    except Exception as e:
        logging.error(f"로그 조회 오류: {e}")
        return jsonify({'error': '로그 조회 실패'}), 500

@admin_bp.route('/api/server/status') 
def get_server_status():
    """서버 상태 종합 정보"""
    try:
        # 각종 로그 파일 크기 확인
        log_files = {
            'server_log': 'logs/server.log',
            'beacon_log': 'logs/beacon_log.json',
            'command_log': 'logs/command_log.json', 
            'exfil_log': 'logs/exfil_log.json',
            'victims_db': 'logs/victims_db.json'
        }
        
        file_info = {}
        for name, path in log_files.items():
            if os.path.exists(path):
                size = os.path.getsize(path)
                file_info[name] = {
                    'exists': True,
                    'size_bytes': size,
                    'size_formatted': format_bytes(size),
                    'modified': datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
                }
            else:
                file_info[name] = {'exists': False}
        
        # 시스템 정보
        system_info = get_system_info()
        
        return jsonify({
            'server_status': 'online',
            'timestamp': datetime.now().isoformat(),
            'system_info': system_info,
            'log_files': file_info,
            'directories': {
                'uploads': os.path.exists('uploads'),
                'downloads': os.path.exists('downloads'), 
                'exfil': os.path.exists('uploads/exfil')
            }
        })
        
    except Exception as e:
        logging.error(f"서버 상태 조회 오류: {e}")
        return jsonify({'error': '서버 상태 조회 실패'}), 500