
from flask import Flask, jsonify, request, render_template_string, send_from_directory
from flask_cors import CORS
from database.db_manager import DatabaseManager
from services.log_processor import LogProcessor
from services.ml_analyzer import MLAnalyzer
from services.alert_system import AlertSystem
from api.routes import api_bp
import os
import sys
import argparse

app = Flask(__name__)
CORS(app)

# Initialize services
db_manager = DatabaseManager()
log_processor = LogProcessor(db_manager)
ml_analyzer = MLAnalyzer(db_manager)
alert_system = AlertSystem(db_manager)

# Register blueprints
app.register_blueprint(api_bp, url_prefix='/api')

@app.route('/')
def index():
    return jsonify({"message": "IoT Device Log Forensic API", "status": "running", "modes": ["api", "cli"]})

@app.route('/dashboard')
def dashboard():
    """Serve the IoT forensic dashboard"""
    try:
        with open('project.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        return jsonify({"error": "Dashboard not found"}), 404

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "database": db_manager.check_connection()})

def run_cli_mode():
    """Run the CLI dashboard"""
    from cli_dashboard import CLIDashboard
    dashboard = CLIDashboard()
    dashboard.run()

def run_api_client():
    """Run the API client"""
    from api_client import IoTForensicAPIClient
    client = IoTForensicAPIClient()
    
    print("🔒 IoT Forensic API Client")
    print("=" * 40)
    
    while True:
        print("\nAPI Client Options:")
        print("1. View devices")
        print("2. View logs")
        print("3. Get analytics")
        print("4. Generate report")
        print("5. Monitor real-time")
        print("6. Exit")
        
        choice = input("Select option (1-6): ")
        
        if choice == "1":
            devices = client.get_devices()
            if devices:
                print(f"\nFound {len(devices)} devices:")
                for device in devices:
                    print(f"  - {device['name']}: {device['status']}")
            else:
                print("No devices found")
                
        elif choice == "2":
            logs = client.get_logs()
            if logs:
                print(f"\nFound {len(logs)} logs:")
                for log in logs[:5]:
                    print(f"  - {log.get('device')}: {log.get('message')[:50]}...")
            else:
                print("No logs found")
                
        elif choice == "3":
            analytics = client.get_analytics()
            if analytics:
                print(f"\nAnalytics:")
                for key, value in analytics.items():
                    print(f"  - {key}: {value}")
            else:
                print("No analytics data")
                
        elif choice == "4":
            client.generate_forensic_report()
            
        elif choice == "5":
            duration = input("Monitor duration in minutes (default 5): ")
            try:
                duration = int(duration) if duration else 5
                client.monitor_real_time(duration)
            except ValueError:
                print("Invalid duration")
                
        elif choice == "6":
            break
        else:
            print("Invalid option")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IoT Device Log Forensic System')
    parser.add_argument('--mode', choices=['api', 'cli', 'client'], default='api',
                       help='Mode to run: api (Flask server), cli (CLI dashboard), or client (API client)')
    parser.add_argument('--port', type=int, default=5000, help='Port for API server')
    parser.add_argument('--host', default='0.0.0.0', help='Host for API server')
    
    args = parser.parse_args()
    
    # Initialize database tables
    db_manager.init_database()
    
    if args.mode == 'cli':
        print("🖥️ Starting CLI Dashboard Mode...")
        run_cli_mode()
    elif args.mode == 'client':
        print("📡 Starting API Client Mode...")
        run_api_client()
    else:
        print(f"🌐 Starting API Server Mode on {args.host}:{args.port}...")
        app.run(host=args.host, port=args.port, debug=True)
