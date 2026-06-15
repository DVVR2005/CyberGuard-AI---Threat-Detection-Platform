"""
AI Advisor chat routes for CyberGuard AI.
"""

from flask import Blueprint, jsonify, request
from routes.auth import token_required
from services.ai_service import generate_security_advice

ai_bp = Blueprint('ai', __name__, url_prefix='/api/ai')


@ai_bp.route('/chat', methods=['POST'])
@token_required
def chat(current_user):
    """
    Handle AI advisor chat prompts.
    Evaluates the security posture of the user's tenant to customize recommendations.
    """
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'success': False, 'error': "Field 'message' is required"}), 400

        user_prompt = data.get('message', '').strip()
        history = data.get('history', [])
        tenant_id = current_user['tenant_id']

        # Generate recommendation
        result = generate_security_advice(
            tenant_id=tenant_id,
            user_prompt=user_prompt,
            chat_history=history
        )

        return jsonify({
            'success': True,
            'response': result['response'],
            'context': result['context']
        }), 200

    except Exception as e:
        return jsonify({'success': False, 'error': f"AI processing failed: {str(e)}"}), 500
