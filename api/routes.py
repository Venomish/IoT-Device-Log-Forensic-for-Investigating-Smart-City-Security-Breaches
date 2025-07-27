from flask import Blueprint, jsonify, request
from datetime import datetime
import json

api_bp = Blueprint('api', __name__)

@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """Get device logs with optional filtering"""
    device = request.args.get('device')
    severity = request.args.get('severity')

    # Sample logs data
    sample_logs = [
        {
            "id": 1,
            "timestamp": "2025-01-26T18:00:00Z",
            "device": "Traffic Camera",
            "severity": "high",
            "message": "Unauthorized access attempt detected",
            "attack_type": "Brute Force"
        },
        {
            "id": 2,
            "timestamp": "2025-01-26T17:30:00Z",
            "device": "Environmental Sensor",
            "severity": "medium",
            "message": "Unusual data pattern detected",
            "attack_type": "Data Exfiltration"
        },
        {
            "id": 3,
            "timestamp": "2025-01-26T17:00:00Z",
            "device": "Smart Streetlight",
            "severity": "high",
            "message": "DDoS attack detected",
            "attack_type": "DDoS"
        }
    ]

    return jsonify(sample_logs)

@api_bp.route('/devices', methods=['GET'])
def get_devices():
    """Get list of monitored devices"""
    devices = [
        {"id": 1, "name": "Traffic Camera", "status": "online"},
        {"id": 2, "name": "Environmental Sensor", "status": "online"},
        {"id": 3, "name": "Smart Streetlight", "status": "offline"},
        {"id": 4, "name": "Surveillance Camera", "status": "online"},
        {"id": 5, "name": "Traffic Signal", "status": "online"}
    ]
    return jsonify(devices)

@api_bp.route('/analytics', methods=['GET'])
def get_analytics():
    """Get analytics data"""
    analytics = {
        "total_logs": 156,
        "anomalies": 23,
        "devices_monitored": 5,
        "high_severity_events": 8
    }
    return jsonify(analytics)