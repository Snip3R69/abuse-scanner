from flask import Flask, render_template, request
from scanner import scan_target

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    error = None
    target_url = request.form.get('target_url', '')
    takedown_type = request.form.get('takedown_type', '')
    company = request.form.get('company', '')
    brand = request.form.get('brand', '')
    
    if request.method == 'POST':
        if target_url:
            results = scan_target(target_url)
        else:
            error = "Please enter a URL or Domain."
            
    return render_template('index.html', 
                           results=results, 
                           error=error, 
                           target_url=target_url,
                           takedown_type=takedown_type,
                           company=company, 
                           brand=brand)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
