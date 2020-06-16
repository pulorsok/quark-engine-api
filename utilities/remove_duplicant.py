import sys
import os
import json

def read_report(report):
    with open(report, "r+") as report_file:
        data = json.load(report_file)
    return data

def found_duplicant(data):
    count = 0
    for a in data["crimes"]:
        for b in data["crimes"]:
            if a["permissions"].sort() == b["permissions"].sort():
                if a["methods"][0] == b["methods"][1] and a["methods"][1] == b["methods"][0]:
                    count += 1
                    print("=====================")
                    print(json.dumps(a, indent=4))
                    print(json.dumps(b, indent=4))
            
    print("count : " + str(count))
FILE = "report_5751cfdf656f2a5ee021940c5448a77e5b921d1510d2abfa520a57d02c74821e0f5c2e4935bea2554c440072d32fc22bb8317a85dabbbc7c9cca9d1c077793c2.json"
PATH = "../data/report/"

data = read_report(PATH + FILE)
found_duplicant(data)
# print(json.dumps(data))
    