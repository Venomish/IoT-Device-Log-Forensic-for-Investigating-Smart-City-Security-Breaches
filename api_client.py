
import requests
import json
from datetime import datetime
import logging

class IoTForensicAPIClient:
    def __init__(self, base_url="http://localhost:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        
    def get_logs(self, device=None, severity=None):
        """Get device logs with optional filtering"""
        params = {}
        if device:
            params['device'] = device
        if severity:
            params['severity'] = severity
            
        try:
            response = self.session.get(f"{self.base_url}/api/logs", params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching logs: {e}")
            return None
            
    def get_devices(self):
        """Get list of monitored devices"""
        try:
            response = self.session.get(f"{self.base_url}/api/devices")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching devices: {e}")
            return None
            
    def get_analytics(self):
        """Get analytics data"""
        try:
            response = self.session.get(f"{self.base_url}/api/analytics")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching analytics: {e}")
            return None
            
    def analyze_security_trends(self):
        """Analyze security trends"""
        logs = self.get_logs()
        if not logs:
            return None
            
        # Analyze trends
        severity_count = {'high': 0, 'medium': 0, 'low': 0}
        attack_types = {}
        device_activity = {}
        
        for log in logs:
            severity = log.get('severity', 'low')
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
            attack_type = log.get('attack_type')
            if attack_type:
                attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
                
            device = log.get('device')
            if device:
                device_activity[device] = device_activity.get(device, 0) + 1
                
        return {
            'severity_distribution': severity_count,
            'attack_types': attack_types,
            'device_activity': device_activity,
            'total_logs': len(logs),
            'analysis_time': datetime.now().isoformat()
        }
        
    def generate_forensic_report(self):
        """Generate a comprehensive forensic report"""
        print("🔍 Generating Forensic Report...")
        
        # Gather data
        devices = self.get_devices()
        logs = self.get_logs()
        analytics = self.get_analytics()
        trends = self.analyze_security_trends()
        
        report = {
            'report_id': f"FR_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'generated_at': datetime.now().isoformat(),
            'summary': {
                'total_devices': len(devices) if devices else 0,
                'total_logs': len(logs) if logs else 0,
                'high_severity_events': len([l for l in logs if l.get('severity') == 'high']) if logs else 0
            },
            'devices': devices,
            'security_trends': trends,
            'analytics': analytics
        }
        
        # Save report
        filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        print(f"✅ Report saved as: {filename}")
        return report
        
    def monitor_real_time(self, duration_minutes=5):
        """Monitor system in real-time"""
        import time
        
        print(f"🔴 Starting real-time monitoring for {duration_minutes} minutes...")
        start_time = time.time()
        end_time = start_time + (duration_minutes * 60)
        
        while time.time() < end_time:
            current_time = datetime.now().strftime('%H:%M:%S')
            print(f"\n[{current_time}] Checking system status...")
            
            # Get recent data
            logs = self.get_logs()
            devices = self.get_devices()
            
            if logs:
                recent_high_severity = [l for l in logs[:10] if l.get('severity') == 'high']
                if recent_high_severity:
                    print(f"🚨 {len(recent_high_severity)} high severity events detected!")
                    for log in recent_high_severity[:3]:
                        print(f"   - {log.get('device')}: {log.get('message')[:50]}...")
                else:
                    print("✅ No immediate threats detected")
            
            # Check device status
            online_devices = len([d for d in devices if d.get('status') == 'online']) if devices else 0
            total_devices = len(devices) if devices else 0
            print(f"📱 Devices: {online_devices}/{total_devices} online")
            
            time.sleep(30)  # Check every 30 seconds
            
        print("\n🔴 Monitoring session completed")

# Usage examples
if __name__ == "__main__":
    # Initialize client
    client = IoTForensicAPIClient()
    
    print("🔒 IoT Forensic API Client")
    print("=" * 40)
    
    # Example usage
    print("1. Getting device list...")
    devices = client.get_devices()
    if devices:
        print(f"Found {len(devices)} devices")
        for device in devices:
            print(f"  - {device['name']}: {device['status']}")
    
    print("\n2. Getting recent logs...")
    logs = client.get_logs()
    if logs:
        print(f"Found {len(logs)} logs")
        high_severity = [l for l in logs if l.get('severity') == 'high']
        print(f"  - {len(high_severity)} high severity events")
    
    print("\n3. Analyzing security trends...")
    trends = client.analyze_security_trends()
    if trends:
        print(f"Total logs analyzed: {trends['total_logs']}")
        print("Severity distribution:", trends['severity_distribution'])
        
    print("\n4. Generating forensic report...")
    report = client.generate_forensic_report()
    
    # Uncomment to start real-time monitoring
    # print("\n5. Starting real-time monitoring...")
    # client.monitor_real_time(duration_minutes=1)
