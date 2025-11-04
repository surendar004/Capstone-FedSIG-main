"""
REST API Routes for FedSIG+ ThreatNet
External API endpoints for integration
"""

from flask import jsonify, request
from datetime import datetime


def setup_api_routes(app, server):
    """
    Setup REST API routes
    
    Args:
        app: Flask application instance
        server: IntegratedServer instance
    """
    
    @app.route('/api/status', methods=['GET'])
    def api_status():
        """Get system status"""
        stats = server.get_system_stats()
        return jsonify({
            'status': 'online',
            'timestamp': datetime.now().isoformat(),
            'data': stats.to_dict()
        })
    
    @app.route('/api/clients', methods=['GET'])
    def api_clients():
        """Get all clients"""
        clients = [profile.to_dict() for profile in server.clients.values()]
        return jsonify({
            'status': 'success',
            'count': len(clients),
            'data': clients
        })
    
    @app.route('/api/clients/<client_id>', methods=['GET'])
    def api_client_detail(client_id):
        """Get specific client details"""
        if client_id not in server.clients:
            return jsonify({'status': 'error', 'message': 'Client not found'}), 404
        
        return jsonify({
            'status': 'success',
            'data': server.clients[client_id].to_dict()
        })
    
    @app.route('/api/iocs', methods=['GET'])
    def api_iocs():
        """Get all IOCs"""
        status_filter = request.args.get('status')
        ioc_type = request.args.get('type')
        threat_level = request.args.get('threat_level')
        
        iocs = server.intel_aggregator.get_all_iocs(status=status_filter)
        
        # Apply filters
        if ioc_type:
            iocs = [ioc for ioc in iocs if ioc.ioc.ioc_type == ioc_type]
        if threat_level:
            iocs = [ioc for ioc in iocs if ioc.ioc.threat_level == threat_level]
        
        return jsonify({
            'status': 'success',
            'count': len(iocs),
            'data': [ioc.to_dict() for ioc in iocs]
        })
    
    @app.route('/api/iocs/<ioc_id>', methods=['GET'])
    def api_ioc_detail(ioc_id):
        """Get specific IOC details"""
        intel = server.intel_aggregator.get_ioc_by_id(ioc_id)
        
        if not intel:
            return jsonify({'status': 'error', 'message': 'IOC not found'}), 404
        
        return jsonify({
            'status': 'success',
            'data': intel.to_dict()
        })
    
    @app.route('/api/trust_scores', methods=['GET'])
    def api_trust_scores():
        """Get all trust scores"""
        scores = server.trust_manager.get_all_trust_scores()
        return jsonify({
            'status': 'success',
            'count': len(scores),
            'data': [score.to_dict() for score in scores]
        })
    
    @app.route('/api/trust_scores/<client_id>', methods=['GET'])
    def api_trust_score_detail(client_id):
        """Get specific client trust score"""
        score = server.trust_manager.get_trust_score_obj(client_id)
        
        if not score:
            return jsonify({'status': 'error', 'message': 'Client not found'}), 404
        
        return jsonify({
            'status': 'success',
            'data': score.to_dict()
        })
    
    @app.route('/api/detections', methods=['GET'])
    def api_detections():
        """Get recent detections"""
        limit = int(request.args.get('limit', 50))
        recent = server.detection_feed[-limit:]
        
        return jsonify({
            'status': 'success',
            'count': len(recent),
            'data': [det.to_dict() for det in recent]
        })
    
    @app.route('/api/intel/statistics', methods=['GET'])
    def api_intel_stats():
        """Get intelligence statistics"""
        stats = server.intel_aggregator.get_statistics()
        return jsonify({
            'status': 'success',
            'data': stats
        })
    
    @app.route('/api/report_threat', methods=['POST'])
    def api_report_threat():
        """Report a threat via API"""
        data = request.get_json()
        
        if not data or 'ioc' not in data or 'client_id' not in data:
            return jsonify({
                'status': 'error',
                'message': 'Missing required fields: ioc, client_id'
            }), 400
        
        try:
            from src.common.models_enhanced import IOC
            
            ioc_data = data['ioc']
            ioc = IOC(
                ioc_id=IOC.generate_ioc_id(ioc_data['ioc_type'], ioc_data['value']),
                ioc_type=ioc_data['ioc_type'],
                value=ioc_data['value'],
                threat_level=ioc_data.get('threat_level', 'medium'),
                source_client=data['client_id'],
                metadata=ioc_data.get('metadata', {})
            )
            
            # Get client trust
            trust_score = server.trust_manager.get_trust_score(data['client_id'])
            
            # Report IOC
            intel = server.intel_aggregator.report_ioc(ioc, data['client_id'], trust_score)
            
            if intel:
                # Broadcast if verified
                server.broadcast_ioc(intel)
                return jsonify({
                    'status': 'success',
                    'message': 'IOC verified and broadcast',
                    'data': intel.to_dict()
                })
            else:
                return jsonify({
                    'status': 'success',
                    'message': 'IOC reported, pending verification',
                    'data': ioc.to_dict()
                })
        
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': str(e)
            }), 500
    
    @app.route('/api/sync_intel', methods=['GET'])
    def api_sync_intel():
        """Sync intelligence for a client"""
        client_id = request.args.get('client_id')
        
        if not client_id:
            return jsonify({
                'status': 'error',
                'message': 'Missing client_id parameter'
            }), 400
        
        # Get all verified IOCs
        iocs = server.intel_aggregator.get_all_iocs(status='verified')
        
        return jsonify({
            'status': 'success',
            'count': len(iocs),
            'data': [ioc.to_dict() for ioc in iocs],
            'timestamp': datetime.now().isoformat()
        })
    
    @app.route('/api/health', methods=['GET'])
    def api_health():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'service': 'FedSIG+ ThreatNet',
            'version': '2.0.0',
            'timestamp': datetime.now().isoformat()
        })
    
    return app