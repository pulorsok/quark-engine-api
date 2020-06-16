import os 
import time




class AnalysisMonitor:
    
    def __init__(self):
        self.work_list = []

    def add_process(self, apk):
        """
            Append apk analysis process into process list
        """
        start_time = time.time()
        work = {
            "apk": apk,
            "progress": "init", 
            "time": start_time
        }
        self.work_list.append(work)

    def update_apk_progress(self, apk, progress):
        """
            Update current apk progress in work list
        """
        for work in self.work_list:
            if work["apk"] == apk:
                work["progress"] == progress
                work["time"] == time.time() - work["time"]
                return True
            return False

    def check_apk_on_process(self, apk):
        """
            Check if the given apk is in analysis process
        """ 
        for process in self.process:
            if process["apk"] == apk:
                return True
            return False
    
    def get_apk_progress(self, apk):
        """
            Return current apk progress in work_list
        """
        for work in self.work_list:
            if work["apk"] == apk:
                work["time"] == time.time() - work["time"]
                return work
            return False

    def remove_apk_process(self, apk):
        """
            Remove given apk process in work_list
        """
        self.work_list[:] = [work for work in self.work_list if work.get("apk") == apk]

    def get_work_list(self):
        """
            Return work_list
        """
        return self.work_list
    

    
