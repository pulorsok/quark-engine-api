import os

import uuid
import datetime
import click
import json
from tqdm import tqdm

from filehash import FileHash

from prettytable import PrettyTable

from quark.Objects.ruleobject import RuleObject
from quark.logo import logo
from quark.Objects.xrule import XRule
from quark.utils.out import print_success, print_info, print_warning
from quark.utils.weight import Weight

APK_PATH = "data/apk/"
RULE_PATH = "data/rules/"
REPORT_PATH = "data/report/"

class ApkAnalysis:
    
    def __init__(self, apk, apk_name):
        path = os.path.join(APK_PATH, apk)
        self.apk = path
        self.apk_name = apk_name
        self.data = None
        self.json_crimes = []

    def analysis(self):
        
        try:
            self.data = XRule(self.apk)
        except:
            print("Error from decompile apk: {}".format(self.apk))
            self.generate_report(result=False)
            return "Error open apk"
        
        

        # Load rules
        rules_list = os.listdir(RULE_PATH)

        
        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(RULE_PATH, single_rule)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            
            try:
                self.data.run(rule_checker)
            except:
                print("Error from analysis from rule: {}".format(single_rule))
                
                continue
            self.data.show_summary_report(rule_checker)
            
            crime, confidence, score, weight = self.data.get_json_report(rule_checker)
            json_crime = {
                "rule": crime,
                "permissions": rule_checker.x1_permission,
                "methods": rule_checker.x2n3n4_comb,
                "confidence": confidence,
                "score": score,
                "weight": weight,
            }
            if json_crime["confidence"] > 0:
                self.json_crimes.append(json_crime)

        json_report = self.generate_report(result=True)

        return json_report


    def _check_risk(self, risk):
        
        risks_list = [
            "Low Risk",
            "Moderate Risk",
            "High Risk"
        ]
        for r in risks_list:
            if r in risk:
                return r

        return "None Risk"

    def generate_report(self, result):

        sha512 = FileHash("sha512")
        f_hash = sha512.hash_file(self.apk)


        if not result:
            json_report = {
                "sample": f_hash,
                "size": os.path.getsize(self.apk),
                "apk-name": self.apk_name,
                "analysis_status": 2,
            }
            return
        

        w = Weight(self.data.score_sum, self.data.weight_sum)
        risk = self._check_risk(w.calculate())

        json_report={
            "sample": f_hash,
            "apk-name": self.apk_name,
            "size": os.path.getsize(self.apk),
            "warnning": risk,
            "total-score": self.data.score_sum,
            "crimes": self.json_crimes,
            "analysis_status": 1,
        }
        name = f_hash + ".json"
        report_path = REPORT_PATH + name
        with open( REPORT_PATH + name, "w+") as report_file:
            json.dump(json_report, report_file, indent=4)
        
        report_file.close()

        return json_report