import os
from os import path
import json
import sys
from flask_flatpages import FlatPages
from flask_frozen import Freezer
from flask import Flask, abort
from flask import request
from flask import render_template
from flask import flash
from flask import redirect
from flask import url_for
from flask import send_from_directory
from flask import send_file

# from flask_cors import CORS, cross_origin

from filehash import FileHash

from model.apk_analysis import ApkAnalysis

from werkzeug.utils import secure_filename


UPLOAD_FOLDER = "data/apk/"
ALLOWED_EXTENSIONS = {'apk'}

app = Flask(__name__)


# CORS(app, resource={r"/.*": {"origins": ["http://quark.xeo.tw"]}})

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORT_FOLDER'] = "data/report/"

pages = FlatPages(app)
freezer = Freezer(app)


""" APP utilities """
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_request
def check():

    if request.host_url != "http://quark.xeo.tw/":
        abort(401)


""" Router """

@app.route('/')
def home():
    return render_template("index.html", static_folder="static" , title="Home")

@app.route('/about')
def about():
    return render_template("about.html", static_folder="static" , title="About")

@app.route('/demo')
def demo():
    return render_template("report.html", static_folder="static" , title="Demo")

@app.route('/report')
def report():
    path = os.path.join(app.root_path, 'data/report')
    report_dir = os.listdir(path)
    reports = []
    for report in report_dir:
        report_file = os.path.join(path, report)
        with open(report_file) as report_f:
            data = json.load(report_f)
        reports.append(data)
    
    return render_template("all_report.html", static_folder="static" , title="Report", reports=reports)



@app.route('/report_detail/<tag>')
def report_detail(tag):
    report_name = "report_" + tag + ".json"
    path = os.path.join(app.root_path, 'data/report')
    report_path = os.path.join(path, report_name)
    with open(report_path) as report:
        report_data = json.load(report)

    
    report.close()
    return render_template("report_detail.html", static_folder="static" , title="Detail", report=report_data)



@app.route('/upload_apk', methods=['POST'])
def upload_apk():
    print(request)
    print(request.files)
    if request.method == 'POST':

        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            print("No file part")
            return redirect(request.url)
        file = request.files['file']

        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            print("No selected file")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            sha512 = FileHash("sha512")
            filename = secure_filename(file.filename)
            
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            f_hash = sha512.hash_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            os.rename(os.path.join(app.config['UPLOAD_FOLDER'], filename), 
                        os.path.join(app.config['UPLOAD_FOLDER'], f_hash))
            


            report_path = os.path.join(app.config['REPORT_FOLDER'], f_hash + ".json")
            if path.exists(report_path):
                print("report exist") 
                return redirect(url_for("json_report", tag=f_hash))



            
            analysis = ApkAnalysis(f_hash, filename)
            report = analysis.analysis()

            if report == "Error open apk":
                return json()


            report_tag = report["sample"]
            # report_path = os.path.join(app.config['REPORT_FOLDER'], "report_" + report["sample"] + ".json")
            # return send_file(report_path)


            return redirect(url_for("json_report", tag=report_tag))
            # return redirect(url_for('report_detail', tag=report["sample"]))




@app.route('/json_report/<path:tag>', methods=['GET', 'POST'])
def json_report(tag):
    name = tag + ".json"
    file_path = os.path.join(app.root_path, 'data/report')
    filepath = os.path.join(file_path, name)
    
    if not path.exists(filepath):
        return "Report not exist"

    return send_file(filepath)

if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'


    if len(sys.argv) > 1 and sys.argv[1] == "build":
        freezer.freeze()
    else:
        app.run(host="0.0.0.0", port=80)