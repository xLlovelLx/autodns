import eventlet
import eventlet.wsgi
from flask import Flask, render_template, request,redirect, url_for, flash
from flask_socketio import SocketIO,join_room, emit
from werkzeug.utils import secure_filename
from scripts.utils import validate_file_path, load_file_lines, save_results_to_file,stop_event
import os
from core.passive import passive_enum
from core.active import active_enum_flask
from core.brute import brute_force, brute_force_flask
from dns_enum.advanced_dns_records import dns_over_https_flask, dns_over_tls_flask
import json
import asyncio
from datetime import datetime
from ruamel.yaml import YAML
from dns_enum.tld_expansion import  tld_expand_flask
# eventlet.monkey_patch()  # Patch standard library to use eventlet for async I/O

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
            if passive:
                output["Passive"] = passive_enum(domain, None, verbose, all_engines=True)
                # if sid:
                socketio.emit('enum_update', {'step': 'Passive', 'result': output["Passive"]})
            if active:
                output["Active"] = active_enum_flask(domain, None, verbose)
                # if sid:
                # socketio.emit('enum_update', {'step': 'Active', 'result': output["Active"]})
            if brute:
                # if sid:
                output["Brute-Force"] = brute_force_flask(domain, wordlist_file, resolver_file)
            if doh:
                output["DoH"] = dns_over_https_flask(domain, output_file=None, verbose=verbose)
                # socketio.emit('enum_update', {'step': 'DoH', 'result': output["DoH"]})
            if dot:
                output["DoT"] = dns_over_tls_flask(domain, output_file=None, verbose=verbose)
                # socketio.emit('enum_update', {'step': 'DoT', 'result': output["DoT"]})
            if tld:
                output["TLD"] = tld_expand_flask(domain, tlds_path=DEFAULT_TLDS, verbose=verbose)
            
               
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
        #socketio.emit('enum_complet', {'result': output}, room=sid)
        
            #socketio.emit('enum_message', {'message': f"Enumeration complete.{output}", 'category': "success"}, room=sid)
        
        # if sid:
        socketio.emit('enum_update', {'step': 'Complete', 'result': output})
    except Exception as e:
        socketio.emit('enum_update', {'step': 'Error', 'result': str(e)})
        
    

@app.route('/', methods=['GET', 'POST'])
def index():
    history=load_history()
    config=load_config()
    result=None
    verbose_output = None
    theme = config.get("ui",{}).get("theme", "dark")  # Default to light theme if not set
    if request.method == 'POST':
        """if "submit_enum" in request.form:
            domain = request.form['domain']
            passive = 'passive' in request.form
            active = 'active' in request.form
            brute = 'brute' in request.form
            verbose = 'verbose' in request.form
            tld = 'tld' in request.form
            wordlist_file = validate_file_path('wordlist_file' in request.form, DEFAULT_SUBDOMAINS)
            resolver_file = validate_file_path('resolver_file' in request.form, DEFAULT_RESOLVERS)
            
            
            
            if 'wordlist_file' in request.files and request.files['wordlist_file'].filename:
                file = request.files['wordlist_file']
                filename = secure_filename(file.filename)
                wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(wordlist_path)
            if 'resolver_file' in request.files and request.files['resolver_file'].filename:
                file = request.files['resolver_file']
                filename = secure_filename(file.filename)
                resolver_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(resolver_file)

            
            params = {
                'domain': domain,
                'passive': passive,
                'active': active,
                'brute': brute,
                'verbose': verbose,
                'tld': tld,
                'wordlist_file': wordlist_file,
                'resolver_file': resolver_file
            }
            
            enumeration_types = []
            if passive: 
                enumeration_types.append('Passive')
            if active: 
                enumeration_types.append('Active')
            if brute: 
                enumeration_types.append('Brute-force')
                
            if params:
                #handle_start_enum(params)  # Start the enumeration in the background
                result,types = run_enumeration(params)
            #thread = threading.Thread(target=run_enumeration, args=(params))
            #thread.start()
            # Wait for the thread to finish
            
            entry = {
                    "domain": domain,
                    "types": list(types),
                    "result_key": os.urandom(8).hex(),
                    "params": params,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "result": result,
                }
            
            #history.insert(0, entry)
            add_history_entry(entry)
            #save_history(history) -- removed for redundancy, now handled in add_history_entry
            flash("Enumeration complete.", "success")
        
        # Handling settings update
        elif "save_config" in request.form:
            # Example: update a config setting (customize as needed)
            new_value = request.form.get("config_option", "")
            config["config_option"] = new_value
            save_config(config)
            flash("Configuration updated.", "info")
        ##flash('Enumeration started, please refresh to see results.', 'info')
       # return redirect(url_for('index'))
       """
       
    # Show latest result if available
    history = load_history()
    if history:
        result = history[0]
    
    
    return render_template(
        "dashboard.html",
        history=load_history(),
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
    return redirect(url_for('index'))

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

    if request.method == 'POST':
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
        
        save_config(config)  # Save the updated configuration to the YAML file
        flash("Settings updated successfully.", "success")
        return redirect(url_for('settings'))
    
    theme = config.get("ui", {}).get("theme", "dark")
    return render_template(
        'settings.html',
        config=config,
        active_page='settings',
        theme=theme
        )

@app.route('/history', methods=['GET'])
def history():
    history = load_history()
    theme = load_config().get("ui", {}).get("theme", "dark")
    return render_template('history.html', history=history, active_page='history', theme=theme)

@app.route('/result/<key>', methods=['GET'])
def results(key):
    result = results_store.get(key, None)
    return render_template('dashboard.html', result=result, key=key, history=load_history())
    
if __name__ == '__main__':
    socketio.run(app,debug=True)