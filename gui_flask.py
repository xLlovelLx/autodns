from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import threading

from core.passive import passive_enum
from core.active import active_enum
from core.brute import brute_force
import json
from datetime import datetime

HISTORY_FILE = 'enumeration_history.json'

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, 'r') as f:
        return json.load(f)

def save_history(history):
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def add_history_entry(domain, enumeration_types, result_key):
    history = load_history()
    entry = {
        'domain': domain,
        'types': enumeration_types,
        'result_key': result_key,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    history.insert(0, entry)  # Most recent first
    save_history(history)

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

results_store = {}

def run_enumeration(params, result_key):
    domain = params['domain']
    passive = params.get('passive')
    active = params.get('active')
    brute = params.get('brute')
    verbose = params.get('verbose')
    tld = params.get('tld')
    wordlist_path = params.get('wordlist_path')
    resolver_file = params.get('resolver_file')

    output = {}
    try:
        if passive:
            output["Passive"] = passive_enum(domain, None, verbose, all_engines=True)
        if active:
            output["Active"] = active_enum(domain, None, verbose)
        if brute:
            import asyncio
            if asyncio.iscoroutinefunction(brute_force):
                output["Brute-force"] = asyncio.run(brute_force(domain, wordlist_path, resolver_file, None, verbose))
            else:
                output["Brute-force"] = brute_force(domain, wordlist_path, resolver_file, None, verbose)
    except Exception as e:
        output["Error"] = str(e)
    results_store[result_key] = output

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form['domain']
        passive = 'passive' in request.form
        active = 'active' in request.form
        brute = 'brute' in request.form
        verbose = 'verbose' in request.form
        tld = 'tld' in request.form

        wordlist_path = None
        resolver_file = None
        if 'wordlist' in request.files and request.files['wordlist'].filename:
            file = request.files['wordlist']
            filename = secure_filename(file.filename)
            wordlist_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(wordlist_path)
        if 'resolver_file' in request.files and request.files['resolver_file'].filename:
            file = request.files['resolver_file']
            filename = secure_filename(file.filename)
            resolver_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(resolver_file)

        result_key = os.urandom(8).hex()
        params = {
            'domain': domain,
            'passive': passive,
            'active': active,
            'brute': brute,
            'verbose': verbose,
            'tld': tld,
            'wordlist_path': wordlist_path,
            'resolver_file': resolver_file
        }
        enumeration_types = []
        if passive: 
            enumeration_types.append('Passive')
        if active: 
            enumeration_types.append('Active')
        if brute: 
            enumeration_types.append('Brute-force')
        thread = threading.Thread(target=run_enumeration, args=(params, result_key))
        thread.start()
        add_history_entry(domain, enumeration_types, result_key)
        flash('Enumeration started, please refresh to see results.', 'info')
        return redirect(url_for('results', key=result_key))

    return render_template('dashboard.html', history=load_history())
    
    
@app.route('/results/<key>', methods=['GET'])
def results(key):
    result = results_store.get(key, None)
    return render_template('dashboard.html', result=result, key=key, history=load_history())
    
if __name__ == '__main__':
    app.run(debug=True)