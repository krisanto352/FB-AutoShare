import os
import sys
import json
import time
import requests
import logging
import traceback
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SubmitField, BooleanField
from wtforms.validators import DataRequired, NumberRange
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("fb_share.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('fb_share')

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'grandpa-fb-share-secret-key')

# Initialize CSRF protection
csrf = CSRFProtect(app)

# File paths for storing cookies and tokens
STORAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'storage')
CONFIG_FILE = os.path.join(STORAGE_DIR, 'config.json')

# Default configuration
DEFAULT_CONFIG = {
    "share_delay": 10,  # Seconds between shares
    "retry_delay": 60,  # Seconds to wait after hitting spam protection
    "max_retries": 3    # Maximum number of retries per post
}

# Ensure storage directory exists
os.makedirs(STORAGE_DIR, exist_ok=True)

# Helper functions
def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            flash('Config file is corrupted. Using default settings.', 'error')
    return DEFAULT_CONFIG.copy()

def parse_cookies(cookie_string):
    cookies = {}
    try:
        for part in cookie_string.split(";"):
            part = part.strip()
            if "=" in part:
                key, value = part.split("=", 1)
                cookies[key.strip()] = value.strip()
        return cookies
    except Exception as e:
        flash(f'Error parsing cookies: {str(e)}', 'error')
        return cookies

def check_token(token, cookies):
    """Check if the token is valid and not expired"""
    try:
        response = requests.get(
            f"https://graph.facebook.com/me?access_token={token}",
            cookies=cookies,
            timeout=10
        )
        if response.status_code == 200:
            return True, "Token is valid", response.json()
        else:
            error_data = response.json()
            error_msg = error_data.get('error', {}).get('message', 'Unknown error')
            if "expired" in error_msg.lower() or "invalid" in error_msg.lower():
                return False, f"Token expired or invalid: {error_msg}", None
            return False, f"Token check failed: {error_msg}", None
    except Exception as e:
        return False, f"Error checking token: {str(e)}", None

def share_post(link, token, cookies, config, callback=None):
    """Share a Facebook post with the given link"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"[{timestamp}] Starting share process for link: {link}")

    delay_seconds = config["share_delay"]
    retry_delay = config["retry_delay"]
    max_retries = config["max_retries"]
    results = []

    # Log configuration
    logger.debug(f"Share delay: {delay_seconds}s, Retry delay: {retry_delay}s, Max retries: {max_retries}")

    # Both token and cookies are required
    if not token or not cookies:
        error_msg = "Error: Both token and cookies are required"
        logger.error(error_msg)
        if callback:
            callback(error_msg, "error")
        return [{"status": "error", "message": error_msg, "timestamp": timestamp}]

    # Validate link format
    if not link or not link.startswith("http"):
        error_msg = "Error: Invalid link format. Must start with http/https"
        logger.error(error_msg)
        if callback:
            callback(error_msg, "error")
        return [{"status": "error", "message": error_msg, "timestamp": timestamp}]

    # More browser-like headers to avoid detection
    header = {
        "authority": "graph.facebook.com",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "accept-language": "en-US,en;q=0.9",
        "cache-control": "max-age=0",
        "sec-ch-ua": '"Google Chrome";v="105", "Not)A;Brand";v="8", "Chromium";v="105"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36",
        "Referer": "https://www.facebook.com/",
        "Origin": "https://www.facebook.com"
    }

    retries = 0
    success = False

    while not success and retries < max_retries:
        # Add delay before each attempt (except the first attempt)
        if retries > 0:
            if callback:
                callback(f"Waiting {retry_delay} seconds before retry {retries}/{max_retries}...", "warning")
            time.sleep(retry_delay)
        else:
            if retries > 0:  # Not the first attempt
                time.sleep(delay_seconds)

        # Use a more reliable approach for sharing
        try:
            # Choose API version based on retry count
            api_version = "v16.0" if retries == 0 else "v13.0" if retries == 1 else "v10.0"
            endpoint = f"https://graph.facebook.com/{api_version}/me/feed"

            # Prepare post data with different parameters based on retry count
            post_data = {
                "link": link,
                "access_token": token
            }

            # Add different parameters based on retry count
            if retries == 0:
                post_data["published"] = "false"
            elif retries == 1:
                post_data["published"] = "true"
                post_data["privacy"] = '{"value":"EVERYONE"}'
            else:
                # For the last retry, try a different approach
                post_data["message"] = "Check this out!"

            # Log request details
            timestamp = datetime.now().strftime("%H:%M:%S")
            logger.info(f"[{timestamp}] Attempt #{retries+1} - Using API endpoint: {endpoint}")
            logger.debug(f"Request data: {post_data}")
            logger.debug(f"Using cookies: {bool(cookies)}")

            if callback:
                callback(f"[{timestamp}] Attempt #{retries+1} - Using API endpoint: {endpoint}", "info")

            # Make the API request
            start_time = time.time()
            response = requests.post(
                endpoint,
                data=post_data,
                headers=header,
                cookies=cookies,
                timeout=30
            )
            request_time = time.time() - start_time

            # Log response details
            logger.info(f"Response received in {request_time:.2f}s with status code: {response.status_code}")

            # Debug information
            if response.status_code != 200:
                logger.warning(f"Non-200 status code: {response.status_code}")
                if callback:
                    callback(f"API Response Status: {response.status_code}", "warning")

            # Parse response
            post = response.json()
            logger.debug(f"Response content: {post}")

        except requests.exceptions.RequestException as e:
            error_msg = f"Request error: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            if callback:
                callback(error_msg, "error")
            post = {"error": {"message": f"Connection error: {str(e)}"}}

        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse response as JSON: {str(e)}"
            logger.error(error_msg)
            if callback:
                callback(error_msg, "error")
            post = {"error": {"message": error_msg}}

        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            if callback:
                callback(error_msg, "error")
            post = {"error": {"message": error_msg}}

        timestamp = datetime.now().strftime("%H:%M:%S")
        if "id" in post:
            success = True
            success_msg = f"Successfully Shared! Post ID: {post['id']}"
            logger.info(f"[{timestamp}] {success_msg}")
            if callback:
                callback(success_msg, "success")
            results.append({
                "status": "success",
                "message": "Successfully shared",
                "post_id": post.get('id', ''),
                "timestamp": timestamp
            })
        else:
            error_msg = post.get('error', {}).get('message', 'Unknown error')
            logger.error(f"[{timestamp}] Failed To Share! Error: {error_msg}")
            logger.error(f"Full response: {post}")
            if callback:
                callback(f"Failed To Share! Error: {error_msg}", "error")

            # Check if it's a spam protection error
            is_spam_error = any(keyword in error_msg.lower() for keyword in ["spam", "limit", "protect", "temporarily blocked", "wait"])

            if is_spam_error:
                logger.warning(f"[{timestamp}] Detected spam protection error: {error_msg}")

                # For temporary blocks, use a much longer delay
                if "temporarily blocked" in error_msg.lower():
                    temp_block_delay = retry_delay * 3  # Triple the retry delay
                    logger.warning(f"[{timestamp}] Account temporarily blocked. Waiting {temp_block_delay} seconds before continuing...")
                    if callback:
                        callback(f"Account temporarily blocked. Waiting {temp_block_delay} seconds before continuing...", "warning")
                    time.sleep(temp_block_delay)

                if retries < max_retries - 1:
                    logger.info(f"[{timestamp}] Retry {retries+1}/{max_retries} - Retrying with longer delay...")
                    if callback:
                        callback(f"Detected spam protection. Retrying with longer delay...", "warning")
                    retries += 1

                    # Try alternative sharing method on retry
                    if retries == 1:
                        logger.info(f"[{timestamp}] Trying alternative sharing method...")
                        if callback:
                            callback("Trying alternative sharing method...", "info")
                        # Use a different API version and endpoint
                        header["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                    elif retries == 2:
                        # For the last retry, try a completely different user agent
                        logger.info(f"[{timestamp}] Trying with mobile user agent...")
                        if callback:
                            callback("Trying with mobile user agent...", "info")
                        header["user-agent"] = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1"
                else:
                    logger.error(f"[{timestamp}] Maximum retries reached after {max_retries} attempts")
                    if callback:
                        callback(f"Maximum retries reached.", "error")
                    results.append({
                        "status": "error",
                        "message": f"Failed after {max_retries} retries: {error_msg}",
                        "timestamp": timestamp
                    })
                    break
            else:
                # For other errors, try one more time with different parameters
                if retries == 0:
                    logger.info(f"[{timestamp}] Non-spam error, trying with different parameters: {error_msg}")
                    if callback:
                        callback("Trying with different parameters...", "info")
                    retries += 1
                else:
                    # If already retried, don't retry again
                    logger.error(f"[{timestamp}] Failed after retry with non-spam error: {error_msg}")
                    results.append({
                        "status": "error",
                        "message": f"Failed: {error_msg}",
                        "timestamp": timestamp
                    })
                    break

    return results

# Forms
class LoginForm(FlaskForm):
    cookie = StringField('Facebook Cookies', validators=[DataRequired()])
    token = StringField('Facebook Access Token', validators=[DataRequired()])
    submit = SubmitField('Login')

class ShareForm(FlaskForm):
    link = StringField('Post Link', validators=[DataRequired()])
    limit = IntegerField('Share Limit', validators=[DataRequired(), NumberRange(min=1, max=100)])
    submit = SubmitField('Share')

class ConfigForm(FlaskForm):
    share_delay = IntegerField('Share Delay (seconds)', validators=[DataRequired(), NumberRange(min=1)])
    retry_delay = IntegerField('Retry Delay (seconds)', validators=[DataRequired(), NumberRange(min=1)])
    max_retries = IntegerField('Max Retries', validators=[DataRequired(), NumberRange(min=1, max=10)])
    submit = SubmitField('Save Settings')

# Routes
@app.route('/')
def index():
    if 'token' not in session or 'cookies' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        cookie_string = form.cookie.data
        token = form.token.data

        # Both cookies and token are required
        cookies = parse_cookies(cookie_string)
        is_valid, message, user_info = check_token(token, cookies)

        if is_valid:
            session['token'] = token
            session['cookies'] = cookie_string
            session['user_name'] = user_info.get('name', 'User')
            session['user_id'] = user_info.get('id', '')
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(f'Login failed: {message}', 'error')

    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'token' not in session or 'cookies' not in session:
        return redirect(url_for('login'))

    share_form = ShareForm()

    # Get user info for display
    user_name = session.get('user_name', 'User')
    user_id = session.get('user_id', '')

    # Get IP address
    try:
        ip = requests.get("https://api.ipify.org", timeout=5).text
    except:
        ip = "Unable to fetch"

    return render_template('dashboard.html',
                          user_name=user_name,
                          user_id=user_id,
                          ip=ip,
                          form=share_form)

@app.route('/share', methods=['POST'])
def share():
    if 'token' not in session or 'cookies' not in session:
        logger.warning("Share attempt without valid session")
        flash('You must be logged in to share posts', 'error')
        return redirect(url_for('login'))

    form = ShareForm()
    if form.validate_on_submit():
        link = form.link.data
        limit = form.limit.data

        # Log share attempt
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info(f"[{timestamp}] Share attempt - Link: {link}, Limit: {limit}")

        token = session.get('token', '')
        cookie_string = session.get('cookies', '')
        cookies = parse_cookies(cookie_string) if cookie_string else {}
        config = load_config()

        # Log configuration
        logger.info(f"Share configuration - Delay: {config['share_delay']}s, Retry delay: {config['retry_delay']}s, Max retries: {config['max_retries']}")

        # Validate token and cookies
        if not token or not cookies:
            logger.error("Missing token or cookies in session")
            flash('Authentication error. Please log in again.', 'error')
            return redirect(url_for('login'))

        # Validate link format
        if not link.startswith('http'):
            logger.warning(f"Invalid link format: {link}")
            flash('Invalid link format. Link must start with http:// or https://', 'error')
            return redirect(url_for('dashboard'))

        # Store sharing parameters in session for the AJAX endpoint to use
        session['share_link'] = link
        session['share_limit'] = limit
        session['share_in_progress'] = True
        session['share_results'] = []

        # Create a form instance to pass CSRF token to the template
        csrf_form = FlaskForm()

        return render_template('sharing.html', link=link, limit=limit, form=csrf_form)

    logger.warning("Invalid form submission")
    flash('Invalid form submission', 'error')
    return redirect(url_for('dashboard'))


@app.route('/api/share/status')
@csrf.exempt
def share_status():
    """Get the current status of the sharing process"""
    if 'share_in_progress' not in session:
        return jsonify({'status': 'error', 'message': 'No sharing process in progress'})

    return jsonify({
        'status': 'in_progress' if session.get('share_in_progress', False) else 'completed',
        'results': session.get('share_results', [])
    })


@app.route('/api/share/start', methods=['POST'])
@csrf.exempt
def start_share():
    """Start the sharing process via AJAX"""
    if 'token' not in session or 'cookies' not in session:
        return jsonify({'status': 'error', 'message': 'Authentication required'})

    if 'share_link' not in session or 'share_limit' not in session:
        return jsonify({'status': 'error', 'message': 'Missing sharing parameters'})

    link = session.get('share_link')
    limit = session.get('share_limit')
    token = session.get('token', '')
    cookie_string = session.get('cookies', '')
    cookies = parse_cookies(cookie_string) if cookie_string else {}
    config = load_config()

    results = []
    success_count = 0
    error_count = 0

    # Define a callback function to update the UI in real-time
    def update_ui(message, status):
        timestamp = datetime.now().strftime("%H:%M:%S")
        update = {
            'message': message,
            'status': status,
            'timestamp': timestamp
        }
        if 'share_results' in session:
            session['share_results'].append(update)
            session.modified = True

    try:
        for i in range(limit):
            logger.info(f"Starting share {i+1}/{limit}")
            update_ui(f"Starting share {i+1}/{limit}", "info")
            start_time = time.time()

            try:
                result = share_post(link, token, cookies, config, callback=update_ui)
                results.extend(result)

                # Count successes and errors
                for r in result:
                    if r.get('status') == 'success':
                        success_count += 1
                    else:
                        error_count += 1

                logger.info(f"Share {i+1}/{limit} completed in {time.time() - start_time:.2f}s")
                update_ui(f"Share {i+1}/{limit} completed in {time.time() - start_time:.2f}s", "info")

                if i < limit - 1:  # Don't delay after the last share
                    logger.info(f"Waiting {config['share_delay']}s before next share")
                    update_ui(f"Waiting {config['share_delay']}s before next share", "info")
                    time.sleep(config['share_delay'])
            except Exception as e:
                logger.error(f"Unexpected error during share {i+1}: {str(e)}")
                logger.error(traceback.format_exc())
                error_count += 1
                error_msg = f"System error: {str(e)}"
                update_ui(error_msg, "error")
                results.append({
                    "status": "error",
                    "message": error_msg,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })

        # Log final results
        logger.info(f"Share operation completed - Success: {success_count}, Errors: {error_count}")
        update_ui(f"Share operation completed - Success: {success_count}, Errors: {error_count}", "success")

        # Mark sharing as complete
        session['share_in_progress'] = False
        session['share_results'] = results

        return jsonify({
            'status': 'completed',
            'success_count': success_count,
            'error_count': error_count,
            'results': results
        })

    except Exception as e:
        logger.error(f"Fatal error in sharing process: {str(e)}")
        logger.error(traceback.format_exc())
        session['share_in_progress'] = False
        return jsonify({
            'status': 'error',
            'message': f"Fatal error: {str(e)}"
        })

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'token' not in session or 'cookies' not in session:
        return redirect(url_for('login'))

    config = load_config()
    form = ConfigForm(
        share_delay=config['share_delay'],
        retry_delay=config['retry_delay'],
        max_retries=config['max_retries']
    )

    if form.validate_on_submit():
        config['share_delay'] = form.share_delay.data
        config['retry_delay'] = form.retry_delay.data
        config['max_retries'] = form.max_retries.data
        save_config(config)
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/debug')
def debug_info():
    # Only allow in debug mode
    if not app.debug:
        flash('Debug mode is disabled', 'error')
        return redirect(url_for('dashboard'))

    debug_data = {
        'session': dict(session),
        'config': load_config(),
        'app_info': {
            'debug': app.debug,
            'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'python_version': sys.version,
        },
        'request_info': {
            'user_agent': request.headers.get('User-Agent'),
            'remote_addr': request.remote_addr,
        }
    }

    # Check if log file exists and get last 20 lines
    log_lines = []
    try:
        if os.path.exists('fb_share.log'):
            with open('fb_share.log', 'r') as f:
                log_lines = f.readlines()[-50:]
    except Exception as e:
        log_lines = [f"Error reading log file: {str(e)}"]

    return render_template('debug.html', debug_data=debug_data, log_lines=log_lines)

if __name__ == '__main__':
    # Create storage directory if it doesn't exist
    os.makedirs(STORAGE_DIR, exist_ok=True)

    # Initialize default config if it doesn't exist
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)

    app.run(debug=True)
