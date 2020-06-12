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
        


    def analysis(self):
        
        data = XRule(self.apk)

        # Load rules
        rules_list = os.listdir(RULE_PATH)

        json_crimes = []
        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(RULE_PATH, single_rule)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            data.run(rule_checker)

            data.show_summary_report(rule_checker)
            
            crime, confidence, score, weight = data.get_json_report(rule_checker)
            json_crime = {
                "rule": crime,
                "permissions": rule_checker.x1_permission,
                "methods": rule_checker.x2n3n4_comb,
                "confidence": confidence,
                "score": score,
                "weight": weight
            }
            if json_crime["confidence"] > 0:
                json_crimes.append(json_crime)

        w = Weight(data.score_sum, data.weight_sum)
        print_warning(w.calculate())
        print_info("Total Score: " + str(data.score_sum))

    
        sha512 = FileHash("sha512")
        f_hash = sha512.hash_file(self.apk)
        path = "/Users/pock/quark/quark-engine-web/data/report/"
        json_report={
            "sample": f_hash,
            "apk-name": self.apk_name,
            "size": os.path.getsize(self.apk),
            "warnning": w.calculate(),
            "total-score": data.score_sum,
            "crimes": json_crimes
        }
        
        name = f_hash + ".json"
        report_path = REPORT_PATH + name
        with open( REPORT_PATH + name, "w+") as report_file:
            json.dump(json_report, report_file, indent=4)
        print(json.dumps(json_report, indent=4))
        report_file.close()
        
        # If command --json output report by json

        print(data.tb)

        return json_report