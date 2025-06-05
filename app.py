# app.py

import os
from flask import Flask, request, jsonify, render_template
from pymongo import MongoClient
from datetime import datetime, timezone
import hmac
import hashlib

# Initialize Flask application
app = Flask(__name__)

# --- Configuration ---
# It's highly recommended to use environment variables for sensitive data like secrets and database URIs.
# For local development, you can set these in your shell or use a .env file with python-dotenv.
# Example:
# export MONGODB_URI="mongodb://localhost:27017/"
# export GITHUB_WEBHOOK_SECRET="your_github_webhook_secret_here" # Set this in GitHub webhook settings

# MongoDB connection
# Default to localhost if MONGODB_URI is not set
MONGO_URI = os.getenv('MONGODB_URI', "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client.github_actions # Database name
events_collection = db.events # Collection name

# GitHub Webhook Secret (for verifying webhook payloads)
# This secret should match the one configured in your GitHub repository's webhook settings.
GITHUB_WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET', 'a_very_secret_key').encode('utf-8')

# --- Helper Functions ---

def verify_signature(payload_body_raw, github_signature_header):
    """
    Verifies the signature of the incoming GitHub webhook payload.
    This ensures the request genuinely came from GitHub and hasn't been tampered with.
    """
    app.logger.debug(f"Received signature header: {github_signature_header}")
    app.logger.debug(f"Payload body type: {type(payload_body_raw)}, length: {len(payload_body_raw)}")
    app.logger.debug(f"Configured secret length: {len(GITHUB_WEBHOOK_SECRET)}")

    if not github_signature_header:
        app.logger.warning("No X-Hub-Signature-256 header found.")
        return False

    try:
        sha_name, signature = github_signature_header.split('=')
        if sha_name != 'sha256':
            app.logger.error(f"Unsupported signature algorithm: {sha_name}")
            return False
    except ValueError:
        app.logger.error(f"Invalid X-Hub-Signature-256 header format: {github_signature_header}")
        return False

    # Calculate the HMAC digest
    # Ensure payload_body_raw is bytes
    if isinstance(payload_body_raw, str):
        payload_body_raw = payload_body_raw.encode('utf-8')

    mac = hmac.new(GITHUB_WEBHOOK_SECRET, payload_body_raw, hashlib.sha256)
    calculated_signature = mac.hexdigest()

    app.logger.debug(f"Signature from header: {signature}")
    app.logger.debug(f"Calculated signature: {calculated_signature}")
    app.logger.debug(f"Signatures match? {hmac.compare_digest(calculated_signature, signature)}")

    # Compare the calculated digest with the one from the header
    return hmac.compare_digest(calculated_signature, signature)

def format_timestamp_utc(timestamp_str):
    """
    Converts an ISO 8601 timestamp string to a UTC formatted string.
    Example: "2021-04-01T21:30:00Z" -> "1st April 2021 - 9:30 PM UTC"
    """
    try:
        # Parse the timestamp string. GitHub usually sends ISO 8601 format.
        # The 'Z' indicates UTC.
        dt_object = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        # Ensure it's explicitly UTC
        dt_object = dt_object.astimezone(timezone.utc)
        # Format as "Day Month Year - HH:MM AM/PM UTC"
        return dt_object.strftime("%d %B %Y - %I:%M %p UTC")
    except ValueError as e:
        app.logger.error(f"Error parsing timestamp: {timestamp_str} - {e}")
        return timestamp_str # Return original if parsing fails

# --- Routes ---

@app.route('/webhook', methods=['POST'])
def github_webhook():
    """
    Receives and processes GitHub webhook payloads.
    Stores relevant data in MongoDB.
    """
    if request.method == 'POST':
        # Get the raw request data, as GitHub signs the raw payload, not the parsed JSON.
        payload_raw = request.data
        payload = request.json # This parses it, for easy access to data

        event_type = request.headers.get('X-GitHub-Event')
        github_signature = request.headers.get('X-Hub-Signature-256')

        # Verify webhook signature for security
        # Pass the raw payload for signature verification
        if not verify_signature(payload_raw, github_signature):
            app.logger.error("Webhook signature verification failed. Returning 403.")
            return jsonify({"status": "error", "message": "Invalid signature"}), 403

        app.logger.info(f"Webhook signature verified successfully for event: {event_type}")

        action_data = {}
        timestamp_raw = None
        author = None
        from_branch = None
        to_branch = None
        request_id = None

        if event_type == 'push':
            # Handle Push event
            author = payload['pusher']['name']
            to_branch = payload['ref'].split('/')[-1] # e.g., 'refs/heads/main' -> 'main'
            timestamp_raw = payload['head_commit']['timestamp'] if 'head_commit' in payload else datetime.now(timezone.utc).isoformat()
            request_id = payload['after'] # Commit hash after the push

            action_data = {
                "author": author,
                "action": "PUSH",
                "to_branch": to_branch,
                "timestamp": format_timestamp_utc(timestamp_raw),
                "request_id": request_id,
                "from_branch": None # Not applicable for simple pushes
            }
            app.logger.info(f"Push event data: {action_data}")

        elif event_type == 'pull_request':
            # Handle Pull Request event
            pr_action = payload['action']
            if pr_action in ['opened', 'closed', 'reopened']: # Focus on relevant PR actions
                author = payload['pull_request']['user']['login']
                from_branch = payload['pull_request']['head']['ref']
                to_branch = payload['pull_request']['base']['ref']
                timestamp_raw = payload['pull_request']['created_at'] if pr_action == 'opened' else \
                                payload['pull_request']['updated_at'] if pr_action == 'reopened' else \
                                payload['pull_request']['closed_at']
                request_id = str(payload['number']) # PR ID

                # Special handling for MERGE action (brownie points)
                if pr_action == 'closed' and payload['pull_request']['merged']:
                    action_data = {
                        "author": author,
                        "action": "MERGE",
                        "from_branch": from_branch,
                        "to_branch": to_branch,
                        "timestamp": format_timestamp_utc(timestamp_raw),
                        "request_id": request_id
                    }
                    app.logger.info(f"Merge (via PR close) event data: {action_data}")
                else:
                    action_data = {
                        "author": author,
                        "action": "PULL_REQUEST",
                        "from_branch": from_branch,
                        "to_branch": to_branch,
                        "timestamp": format_timestamp_utc(timestamp_raw),
                        "request_id": request_id
                    }
                    app.logger.info(f"Pull Request event data: {action_data}")
            else:
                app.logger.info(f"Ignoring pull_request action: {pr_action}")
                return jsonify({"status": "ignored", "message": f"Ignoring PR action: {pr_action}"}), 200

        # Add a general timestamp for MongoDB insertion
        action_data['received_at'] = datetime.now(timezone.utc)

        if action_data:
            try:
                events_collection.insert_one(action_data)
                app.logger.info("Event successfully stored in MongoDB.")
                return jsonify({"status": "success", "message": "Event received and stored"}), 200
            except Exception as e:
                app.logger.error(f"Error storing event in MongoDB: {e}")
                return jsonify({"status": "error", "message": "Failed to store event"}), 500
        else:
            app.logger.info(f"No relevant data extracted for event type: {event_type}")
            return jsonify({"status": "ignored", "message": f"Event type {event_type} not processed"}), 200
    else:
        return jsonify({"status": "error", "message": "Method not allowed"}), 405

@app.route('/api/events', methods=['GET'])
def get_events():
    """
    API endpoint to fetch the latest GitHub events from MongoDB.
    Returns events sorted by their `received_at` timestamp in descending order.
    """
    try:
        # Fetch all events, sorted by the time they were received, newest first
        # _id is MongoDB's default unique ID, can also be used for sorting if needed
        events = list(events_collection.find().sort("received_at", -1))

        # Convert ObjectId to string for JSON serialization
        for event in events:
            event['_id'] = str(event['_id'])

        app.logger.info(f"Fetched {len(events)} events from MongoDB.")
        return jsonify(events), 200
    except Exception as e:
        app.logger.error(f"Error fetching events from MongoDB: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch events"}), 500

@app.route('/')
def index():
    """
    Serves the main HTML page for the UI.
    """
    return render_template('index.html')

# --- Run the Flask App ---
if __name__ == '__main__':
    # Set Flask's logger level to DEBUG to see the detailed signature logs
    app.logger.setLevel('DEBUG')
    # For development, run with debug=True. In production, use a WSGI server like Gunicorn.
    app.run(debug=True, host='0.0.0.0', port=5000)
