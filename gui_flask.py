import io
import eventlet
import eventlet.wsgi
from flask import Flask, render_template, request, Response,redirect, send_file, url_for, flash
from flask_socketio import SocketIO,join_room, emit
from werkzeug.utils import secure_filename
from scripts.utils import validate_file_path, load_file_lines, save_results_to_file,stop_event
import os
import logging
from core.passive import passive_enum
from core.active import active_enum_flask
from core.brute import brute_force, brute_force_flask
from dns_enum.advanced_dns_records import dns_over_https_flask, dns_over_tls_flask
import json
import asyncio
from datetime import datetime
from ruamel.yaml import YAML
from dns_enum.tld_expansion import  tld_expand_flask
from dns_enum.graph import visualize_dns_graph, generate_graph_image_from_history
# eventlet.monkey_patch()  # Patch standard library to use eventlet for async I/O

# Setup audit logger
audit_logger = logging.getLogger('audit')
audit_logger.setLevel(logging.INFO)
audit_handler = logging.FileHandler(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'audit.log'))
audit_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
audit_handler.setFormatter(audit_formatter)
audit_logger.addHandler(audit_handler)

# Get the default paths for subdomains and resolvers
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SUBDOMAINS = os.path.join(BASE_DIR, "data", "subdomains.txt")
DEFAULT_RESOLVERS = os.path.join(BASE_DIR, "data", "resolvers.txt")
DEFAULT_TLDS = os.path.join(BASE_DIR, "data", "tlds.txt")
HISTORY_FILE = os.path.join(BASE_DIR, "enumeration_history.json")
CONFIG_FILE = os.path.join(BASE_DIR, "config.yaml")

app = Flask(__name__)
socketio = SocketIO(app,async_mode='threading')  # Use threading for async mode
app.secret_key = 'secret'
UPLOAD_FOLDER = 'data'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

results_store = {}

def load_config():
    yaml = YAML()
    yaml.preserve_quotes = True  # Preserve quotes in the YAML file
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return yaml.load(f)
    #return {}

    
def save_config(cfg):
    yaml = YAML()
    yaml.preserve_quotes = True  # Preserve quotes in the YAML file
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(cfg, f)

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, 'r') as f:
        return json.load(f)

def save_history(history):
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def add_history_entry(entry):
    history = load_history()
    entry = {
        'domain': entry.get("domain"),
        "types": entry.get("types", []),  # Ensure types is a list
        'result_key': entry.get("result_key"),
        'params': entry.get("params"),
        'timestamp': entry.get("timestamp"),
        'result':entry.get("result")
    }
    history.insert(0, entry)  # Most recent first
    save_history(history)

"""def run_enumeration(params,sid):
    
    domain = params['domain']
    passive = params.get('passive')
    active = params.get('active')
    brute = params.get('brute')
    verbose = params.get('verbose')
    tld = params.get('tld')
    wordlist_file = params.get('wordlist_file')
    resolver_file = params.get('resolver_file')
    
    if not domain:
        emit('enum_update', {'step': 'Error', 'result': 'Domain is required.'}, room=sid)
        return 
    
    output = {}
    try:
        if passive:
            output["Passive"] = passive_enum(domain, None, verbose, all_engines=True)
            if sid:
                socketio.emit('enum_update', {'step': 'Passive', 'result': output["Passive"]}, room=sid)
        if active:
            output["Active"] = active_enum(domain, None, verbose)
            if sid:
                socketio.emit('enum_update', {'step': 'Active', 'result': output["Active"]}, room=sid)
        if brute:
            #loop = asyncio.get_event_loop()
            output["Brute-Force"] = brute_force_flask(params, wordlist_file, resolver_file, sid, verbose)
            if sid:
                socketio.emit('enum_update', {'step': 'Brute-Force', 'result': output["Brute-Force"]}, room=sid)
            if asyncio.iscoroutinefunction(brute_force):
                output["Brute-force"] = asyncio.run(handle_start_enum(params))
            else:
                output["Brute-force"] = brute_force(domain, wordlist_file, resolver_file, None, verbose)
    except Exception as e:
        output["Error"] = str(e)
        if sid:
            socketio.emit('enum_update', {'step':'Error','results': str(e)}, room=sid)
    results_store = {
        'domain': domain,
        'types': list(output.keys()),
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'result': output#f"Results for {params['domain']} with {params}"
        
    }
    return output,output.keys()"""


@socketio.on('stop_enum')
def handle_stop_enum():
    stop_event.set()

@socketio.on('start_enum')
def handle_start_enum(params):
    audit_logger.info(f"Enumeration started with params: {params}")
    history = load_history()
    # Ensure the request has a session ID
    # if not request.sid:
        # emit('enum_update', {'step': 'Error', 'result': 'Session ID not found.'})
        # return
    # sid = request.sid
    # join_room(sid)
    # Run enumeration in a background thread
    input_type = params.get('inputType', 'domain')
    domain = params.get('domain', '').strip()
    ptr = params.get('ptr', '').strip()
    passive = params.get('passive', False)
    active = params.get('active', False)
    brute = params.get('brute', False)
    verbose = params.get('verbose', False)
    wordlist_file = validate_file_path(params.get('wordlist_file'), DEFAULT_SUBDOMAINS)
    resolver_file = validate_file_path(params.get('resolver_file'), DEFAULT_RESOLVERS)
    tld = params.get('tld', False)
    doh = params.get('doh', False)
    dot = params.get('dot', False)
    
    if not domain and not ptr:
        emit('enum_update', {'step': 'Error', 'result': 'Domain/ptr is required.'})
        return
    output = {}
    try:
        if input_type == 'ptr' and ptr:
            from dns_enum.ptr_lookup import ptr_lookup_flask
            output["PTR"] = ptr_lookup_flask(ptr, verbose)
        else:
                # if sid:
            
            if active:
                output["Active"] = active_enum_flask(domain, None, verbose)
                # if sid:
                # socketio.emit('enum_update', {'step': 'Active', 'result': output["Active"]})   
            if doh:
                output["DoH"] = dns_over_https_flask(domain, output_file=None, verbose=verbose)
                # socketio.emit('enum_update', {'step': 'DoH', 'result': output["DoH"]})
            if dot:
                output["DoT"] = dns_over_tls_flask(domain, output_file=None, verbose=verbose)
                # socketio.emit('enum_update', {'step': 'DoT', 'result': output["DoT"]})
            if tld:
                output["TLD"] = tld_expand_flask(domain, tlds_path=DEFAULT_TLDS, verbose=verbose)
            if passive:
                output["Passive"] = passive_enum(domain, None, verbose, all_engines=True)
                socketio.emit('enum_update', {'step': 'Passive', 'result': output["Passive"]})
            if brute:
                # if sid:
                output["Brute-Force"] = brute_force_flask(domain, wordlist_file, resolver_file)
            

               
        """results_store[] = {
            'domain': domain,
            'types': list(output.keys()),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'result': output
        }"""

        entry = {
            "domain": ptr if input_type == 'ptr' else domain,
            "types": list(output.keys()),
            "result_key": os.urandom(8).hex(),
            "params": params,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "result": output
        }
        history.insert(0, entry)
        add_history_entry(entry)
            #save_history(history) -- removed for redundancy, now handled in add_history_entry
        #socketio.emit('enum_complete', {'result': output}, room=sid)
        
            #socketio.emit('enum_message', {'message': f"Enumeration complete.{output}", 'category': "success"}, room=sid)
        
        # if sid:
        socketio.emit('enum_complete', {'step': 'Complete', 'result': output})
        
    except Exception as e:
        socketio.emit('enum_update', {'step': 'Error', 'result': str(e)})
        audit_logger.error(f"Enumeration error: {str(e)}")
    finally:
        # Ensure the stop event is cleared after enumeration completes
        stop_event.clear()
        #leave_room(sid)
    if output:
            return render_template(
            "dashboard.html",
            history=load_history(),
            result=output,
            active_page='dashboard',
            theme=load_config().get("ui", {}).get("theme", "dark")  # Default to dark theme if not set  
        )    
        
    

@app.route('/', methods=['GET', 'POST'])
def index():
    history=load_history()
    config=load_config()
    result=None
    verbose_output = None
    theme = config.get("ui",{}).get("theme", "dark")  # Default to light theme if not set
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        passive = 'passive' in request.form
        active = 'active' in request.form
        brute = 'brute' in request.form
        verbose = 'verbose' in request.form
        tld = 'tld' in request.form
        wordlist_file = None
        resolver_file = None

        if 'wordlist_file' in request.files and request.files['wordlist_file'].filename:
            file = request.files['wordlist_file']
            filename = secure_filename(file.filename)
            wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(wordlist_path)
            wordlist_file = wordlist_path
        if 'resolver_file' in request.files and request.files['resolver_file'].filename:
            file = request.files['resolver_file']
            filename = secure_filename(file.filename)
            resolver_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(resolver_file)

        results = {}
        enumeration_types = []
        if passive:
            enumeration_types.append('Passive')
        if active:
            enumeration_types.append('Active')
        if brute:
            enumeration_types.append('Brute-force')

        output = {}
        try:
            if active:
                output["Active"] = active_enum_flask(domain, None, verbose)
            if tld:
                output["TLD"] = tld_expand_flask(domain, tlds_path=DEFAULT_TLDS, verbose=verbose)
            if passive:
                output["Passive"] = passive_enum(domain, None, verbose, all_engines=True)
            if brute:
                output["Brute-Force"] = brute_force_flask(domain, wordlist_file, resolver_file)
        except Exception as e:
            output["Error"] = str(e)
        results[domain] = output

        entry = {
            "domain": domain,
            "types": list(output.keys()),
            "result_key": os.urandom(8).hex(),
            "params": {
                "domain": domain,
                "passive": passive,
                "active": active,
                "brute": brute,
                "verbose": verbose,
                "tld": tld,
                "wordlist_file": wordlist_file,
                "resolver_file": resolver_file
            },
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "result": output
        }
        add_history_entry(entry)

        results = {}
        enumeration_types = []
        if passive:
            enumeration_types.append('Passive')
        if active:
            enumeration_types.append('Active')
        if brute:
            enumeration_types.append('Brute-force')

        for domain in domains:
            output = {}
            try:
                if active:
                    output["Active"] = active_enum_flask(domain, None, verbose)
                if tld:
                    output["TLD"] = tld_expand_flask(domain, tlds_path=DEFAULT_TLDS, verbose=verbose)
                if passive:
                    output["Passive"] = passive_enum(domain, None, verbose, all_engines=True)
                if brute:
                    output["Brute-Force"] = brute_force_flask(domain, wordlist_file, resolver_file)
            except Exception as e:
                output["Error"] = str(e)
            results[domain] = output

            entry = {
                "domain": domain,
                "types": list(output.keys()),
                "result_key": os.urandom(8).hex(),
                "params": {
                    "domain": domain,
                    "passive": passive,
                    "active": active,
                    "brute": brute,
                    "verbose": verbose,
                    "tld": tld,
                    "wordlist_file": wordlist_file,
                    "resolver_file": resolver_file
                },
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "result": output
            }
            add_history_entry(entry)

        flash("Enumeration complete.", "success")
        result = results

    # Show latest result if available
    history = load_history()
    if history and not result:
        result = history[0]

    return render_template(
        "dashboard.html",
        history=history,
        result=result,
        config=config,
        active_page='dashboard',
        theme=theme
    )
    #return render_template('dashboard.html', result=result ,history=load_history())
    
@app.route('/delete_history/<result_key>', methods=['POST'])
def delete_history(result_key):
    history = load_history()
    new_history = [entry for entry in history if entry['result_key'] != result_key]
    save_history(new_history)
    flash("Enumeration history entry deleted.", "success")
    return redirect(url_for('history'))

@app.route('/redo_history/<result_key>', methods=['POST'])
def redo_history(result_key):
    history = load_history()
    entry = next((h for h in history if h["result_key"] == result_key), None)
    if entry:
        params = entry["params"]
        result = entry["result"]
        types = set(entry["types"])  # Use a set to avoid duplicates
        new_entry = {
            "domain": params["domain"],
            "types": list(types),
            "result_key": os.urandom(8).hex(),
            "params": params,
            "timestamp": entry["timestamp"],
            "result": result,
        }
        history.insert(0, new_entry)
        save_history(history)
        #add_history_entry(new_entry["domain"], new_entry["params"]["types"], new_entry["result_key"], new_entry["params"])
        flash("Enumeration re-run complete.", "info")
    else:
        flash("History entry not found.", "danger")
    return redirect(url_for("index"))

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    config = load_config()  # Load the current configuration from the YAML file

    audit_log_content = None
    if request.method == 'POST':
        if 'load_audit' in request.form:
            try:
                with open('audit.log', 'r') as f:
                    audit_log_content = f.read()
            except Exception as e:
                audit_log_content = f"Error reading audit log: {str(e)}"
        else:
            theme = request.form.get("theme", {})
            config['ui']['theme'] = theme  # Update the theme in the configuration
            
            # Update API keys
            for key in config["api_keys"]:
                form_key = f"api_keys[{key}]"
                if form_key in request.form:
                    #for key in config['api_keys']:
                    config['api_keys'][key] = request.form.get(form_key, config['api_keys'][key])

            # Update network settings
            for key in config['network']:
                form_key = f"network[{key}]"
                if form_key in request.form:
                    config['network'][key] = request.form.get(form_key, config['network'][key])
            #if 'network[timeout]' or 'network[retries]' in request.form:
            #   config['network']['timeout'] = int(request.form.get("network[timeout]", config['network']['timeout']))
            #  config['network']['retries'] = int(request.form.get("network[retries]", config['network']['retries']))
            
            audit = request.form.get("audit", "off")
            config ['audit'] = audit == 'on'  # Convert to boolean
            save_config(config)  # Save the updated configuration to the YAML file
            flash("Settings updated successfully.", "success")
            return redirect(url_for('settings'))
    
    theme = config.get("ui", {}).get("theme", "dark")
    return render_template(
        'settings.html',
        config=config,
        active_page='settings',
        theme=theme,
        audit_log_content=audit_log_content
        )

@app.route('/audit_log', methods=['GET'])
def get_audit_log():
    try:
        with open('audit.log', 'r') as f:
            content = f.read()
        return content, 200, {'Content-Type': 'text/plain; charset=utf-8'}
    except Exception as e:
        return f"Error reading audit log: {str(e)}", 500

@app.route('/history', methods=['GET'])
def history():
    history = load_history()
    domain_filter = request.args.get('domain', '').strip().lower()
    type_filter = request.args.get('type', '').strip().lower()

    if domain_filter or type_filter:
        filtered_history = []
        for entry in history:
            domain_match = True
            type_match = True
            if domain_filter:
                domain_match = domain_filter in entry.get('domain', '').lower()
            if type_filter:
                types = [t.lower() for t in entry.get('types', [])]
                type_match = type_filter in types
            if domain_match and type_match:
                filtered_history.append(entry)
        history = filtered_history

    theme = load_config().get("ui", {}).get("theme", "dark")
    return render_template('history.html', history=history, active_page='history', theme=theme)

@app.route('/history/<result_key>', methods=['GET'])
def view_history_entry(result_key):
    history = load_history()
    entry = next((h for h in history if h['result_key'] == result_key), None)
    if not entry:
        return "History entry not found", 404
    theme = load_config().get("ui", {}).get("theme", "dark")
    return render_template('history_entry.html', entry=entry, active_page='history', theme=theme)


@app.route('/export_history/<result_key>', methods=['GET'])
def export_history(result_key):
    history = load_history()
    entry = next((h for h in history if h['result_key'] == result_key), None)
    if not entry:
        return "History entry not found", 404
    # Prepare JSON data for download
    json_data = json.dumps(entry, indent=2)
    # Create a BytesIO stream and write the JSON data
    buffer = io.BytesIO()
    buffer.write(json_data.encode('utf-8'))
    buffer.seek(0)
    filename = f"history_export_{result_key}.json"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/json')

@app.route('/result/<key>', methods=['GET'])
def results(key):
    result = results_store.get(key, None)
    return render_template('dashboard.html', result=result, key=key, history=load_history())


@app.route('/graph_image')
def graph_image():
    # Get result_key from query params to identify enumeration or history entry
    result_key = request.args.get('result_key')
    # Load history and find matching entry
    history = load_history()
    entry = next((h for h in history if h['result_key'] == result_key), None)
    if not entry:
        return "Graph data not found", 404
    # Use helper function to generate image bytes from history entry
    img_bytes = generate_graph_image_from_history(entry)
    return Response(img_bytes, mimetype='image/png')

if __name__ == '__main__':
    socketio.run(app,debug=True)
