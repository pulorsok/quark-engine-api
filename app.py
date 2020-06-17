import os
from os import path
import json
import sys
import uuid

from flask_flatpages import FlatPages
from flask_frozen import Freezer
from flask import Flask, abort, jsonify
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

from utilities.quark_monitor import AnalysisMonitor

from werkzeug.utils import secure_filename
import werkzeug

from saveserver import current_milli_time, intWithCommas, measure_spent_time

ALLOWED_EXTENSIONS = {'apk'}

app = Flask(__name__)


app.config['UPLOAD_FOLDER'] = "data/apk_temp/"
app.config['REPORT_FOLDER'] = "data/report/"
app.config['APK_FOLDER'] = "data/apk/"

monitor = AnalysisMonitor()
pages = FlatPages(app)
freezer = Freezer(app)


""" APP utilities """
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS




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
            print("No file part")
            return jsonify(
                status=0,
                message="File post error"
            )

        file = request.files['file']

        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            print("No selected file")
            return jsonify(
                status=3,
                message="No selected file"
            )

        if not file:
            print("File upload failed")
            return jsonify(
                status=3,
                message="File upload failed"
            )

        
        sha512 = FileHash("sha512")
        filename = str(uuid.uuid4())
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Storing apk in server
        try:
            file.save(file_path)
            f_hash = sha512.hash_file(file_path)
            # os.rename(os.path.join(app.config['UPLOAD_FOLDER'], filename), 
            #             os.path.join(app.config['UPLOAD_FOLDER'], f_hash))
            
        except:
            print("Apk store failed")
            print("Apk name: {}\n Apk hash: {}".format(filename, f_hash))
            return jsonify(
                status=3,
                message="File upload failed",
                report=None
            )
        
        for work in monitor.get_work_list():
            print(work)
        check = monitor.get_apk_progress(f_hash)
        print("check: {}".format(check))
        
        if check:
            print("Current apk on progress: {}\nprogress: {}\nspend time: {}".format(
                check["apk"],
                check["progress"],
                check["time"]
            ))
            return jsonify(
                stauts=7,
                message="Apk on analysis progress",
                report=None
            )
        monitor.add_process(f_hash)
        

        report_path = os.path.join(app.config['REPORT_FOLDER'], f_hash + ".json")

        # Check if report of the apk exist
        if path.exists(report_path):
            print("Report exist") 
            print("Response report for apk: {}".format(f_hash))
            return redirect(url_for("json_report", tag=f_hash))

        
        # Start analysis apk
        analysis = ApkAnalysis(file_path, file.filename, f_hash)
        monitor.update_apk_progress(f_hash, "analyzing...")
        report = analysis.analysis()
        monitor.remove_apk_process(f_hash)
        

        # If analysis apk occure error
        if report == "Error open apk":
            print("Failed parse apk: {}".format(f_hash))
            return jsonify(
                status=2,
                message="Apk analysis failed"
            )
        
        # Store analysis success apk
        file.save(os.path.join(app.config['APK_FOLDER'], f_hash))


        report_tag = report["sample"]
        return redirect(url_for("json_report", tag=report_tag))



@app.route('/json_report/<path:tag>', methods=['GET', 'POST'])
def json_report(tag):

    # Open report by apk hash
    name = tag + ".json"
    file_path = os.path.join(app.root_path, 'data/report')
    filepath = os.path.join(file_path, name)
    
    # Check report exist
    if not path.exists(filepath):
        print("Access report not exist, haven't upload apk yet")
        return jsonify(
            status=4,
            message="Report not exist"
        )

    # Read report
    with open(filepath, "r") as report_f:
        report = json.load(report_f)
    
    # Check analysis status
    analysis_status = report["analysis_status"]
    
    if analysis_status == 0:
        result = {
            "status": analysis_status,
            "message": "Apk analysis failed cause unknown error",
            "report": None
        }

    if analysis_status == 1:
        result = {
            "status": analysis_status,
            "message": "Analysis success",
            "report": report
        }

    if analysis_status == 2:
        result = {
            "status": analysis_status,
            "message": "Apk parse failed",
            "report": None
        }
    return jsonify(result)

if __name__ == '__main__':
    app.secret_key = 'super secret key'
    app.config['SESSION_TYPE'] = 'filesystem'


    if len(sys.argv) > 1 and sys.argv[1] == "build":
        freezer.freeze()
    else:
        app.run(debug=True, host="0.0.0.0", port=5000)