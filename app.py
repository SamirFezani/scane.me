from flask import Flask, jsonify, render_template
from flask_cors import CORS
import os
import json

app = Flask(__name__)
CORS(app)  # Activer CORS pour toutes les routes de l'application

@app.route('/scan_results')
def get_scan_results():
    if os.path.exists('scan_results.json') and os.path.getsize('scan_results.json') > 0:
        with open('scan_results.json', 'r') as json_file:
            scan_data = json.load(json_file)
        return jsonify(scan_data)
    else:
        return jsonify({"error": "Aucun résultat de scan disponible."})

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
