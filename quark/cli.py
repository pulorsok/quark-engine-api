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

logo()


@click.command()
@click.option("--jreport", "-j", is_flag=True)
@click.option("--generate", "-g", is_flag=True)
@click.option("--reports", "-p", is_flag=True)
@click.option("--summary", "-s", is_flag=True, help='show summary report')
@click.option("--detail", "-d", is_flag=True, help="show detail report")
@click.option(
    "-a", "--apk", help="APK file", type=click.Path(exists=True, file_okay=True, dir_okay=True),
    required=True,
)
@click.option(
    "-r", "--rule", help="Rules folder need to be checked",
    type=click.Path(exists=True, file_okay=False, dir_okay=True), required=True,
)
def entry_point(jreport, reports, generate, summary, detail, apk, rule):
    """Quark is an Obfuscation-Neglect Android Malware Scoring System"""

    if generate:
        # Generate rules
        # Load rules
        rules_list = os.listdir(rule)
        
        # Load apks
        apk_list = os.listdir(apk)

        # Pretty Table Output
        tb = PrettyTable()
        tb.field_names = ["Count", "Rule No.", "crime", "confidence"]
        tb.align = "l"

        
        filted_rules = []
        # count filting rule amount
        rule_count = 0
        for apk_file in apk_list:
            apk_file = os.path.join(apk, apk_file)
            data = XRule(apk_file)
            print("Analyzing {} ====".format(apk_file))

            for single_rule in tqdm(rules_list):
                rulepath = os.path.join(rule, single_rule)
                rule_checker = RuleObject(rulepath)

                # Run the checker
                data.run(rule_checker)
               

                confidence = data.get_conf(rule_checker)
                # only get 100% confidence
                if confidence > 4:
                    
                    tb.add_row([
                        rule_count,
                        single_rule,
                        rule_checker.crime,
                        str(confidence * 20) + "%"
                    ])
                    rule_count += 1
                    filted_rules.append(single_rule)


        # open rule list file
        LIST_FILE_PATH = "../android_rule/quark_android_rule/data/"
        with open(LIST_FILE_PATH + "rule_list", "w+") as rule_list_file:
            rule_list_file.writelines("%s\n" % line for line in filted_rules)

        rule_list_file.close()
        print(tb)
    if reports:
        # show summary report
        # Load APK
        

        # Load rules
        rules_list = os.listdir(rule)
        
        # Loads apks
        apk_list = []
        try:
            apk_list = os.listdir(apk)
        except:
            
            a = apk.split('/')[-1]
            apk = apk.replace(a, "")
            apk_list = [a]
            pass
        

        

        for apk_file in apk_list:
            json_crimes = []
            apk_file = os.path.join(apk, apk_file)
            print("now analyze: " + apk_file)
            data = XRule(apk_file)
            for single_rule in tqdm(rules_list):
                
                rulepath = os.path.join(rule, single_rule)
                rule_checker = RuleObject(rulepath)

                # Run the checker
                try:
                    data.run(rule_checker)
                except:
                    pass
                

                data.show_summary_report(rule_checker)
                
                crime, confidence, score, weight = data.get_json_report(rule_checker)
                if crime == "":
                    continue
                json_crime = {
                    "_id": str(uuid.uuid4()),
                    "rule": crime,
                    "permissions": rule_checker.x1_permission,
                    "methods": rule_checker.x2n3n4_comb,
                    "confidence": confidence,
                    "score": score,
                    "weight": weight
                }
                check = True
                if json_crime["confidence"] > 0:
                    for j in json_crimes:
                        if j["permissions"].sort() == json_crime["permissions"].sort():
                            if j["methods"][0] == json_crime["methods"][1] and j["methods"][1] == json_crime["methods"][0]:
                                # count += 1
                                check = False
                                break
                    if check:
                        json_crimes.append(json_crime)     
 
                   

           



            w = Weight(data.score_sum, data.weight_sum)
            print_warning(w.calculate())
            print_info("Total Score: " + str(data.score_sum))
            
            # If command --json output report by json
            if jreport:
                sha512 = FileHash("sha512")
                f_hash = sha512.hash_file(apk_file)
                path = "/Users/pock/quark/quark-engine-web/data/report/"
                json_report={
                    "_id": str(uuid.uuid4()),
                    "sample": f_hash,
                    "apk-name": apk_file.split('/')[-1],
                    "size": os.path.getsize(apk_file),
                    "warnning": w.calculate(),
                    "total-score": data.score_sum,
                    "last-update": datetime.datetime.now().strftime("%c"),
                    "crimes": json_crimes
                }
                
                name = "report_" + f_hash + ".json"
                with open( path + name, "w+") as report_file:
                    json.dump(json_report, report_file, indent=4)
                
                report_file.close()
        # print(data.tb)


    if summary:
        # show summary report
        # Load APK
        data = XRule(apk)

        # Load rules
        rules_list = os.listdir(rule)
        
        json_crimes = []
        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(rule, single_rule)
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
        
        # If command --json output report by json
        if jreport:
            sha512 = FileHash("sha512")
            f_hash = sha512.hash_file(apk)
            path = "/Users/pock/quark/quark-engine-web/data/report/"
            json_report={
                "sample": f_hash,
                "apk-name": apk.split('/')[-1],
                "size": os.path.getsize(apk),
                "warnning": w.calculate(),
                "total-score": data.score_sum,
                "crimes": json_crimes
            }
            
            name = "report_" + f_hash + ".json"
            with open( path + name, "w+") as report_file:
                json.dump(json_report, report_file, indent=4)
            print(json.dumps(json_report, indent=4))
            report_file.close()
        print(data.tb)

    if detail:
        # show summary report

        # Load APK
        data = XRule(apk)

        # Load rules
        rules_list = os.listdir(rule)

        for single_rule in tqdm(rules_list):
            rulepath = os.path.join(rule, single_rule)
            print(rulepath)
            rule_checker = RuleObject(rulepath)

            # Run the checker
            data.run(rule_checker)

            data.show_detail_report(rule_checker)
            print_success("OK")


if __name__ == '__main__':
    entry_point()
