import os
import re
import csv
import json
import sys
from collections import defaultdict
import subprocess
from IOC import ioc
import time

# Comment the 3 below if u all havent pip install

from virustotal import vtapi
from pestaticanalyzer import staticanalysis
from tsmodel import test,dataset

class ModulesControler:


	PWS_DUMP_PATH 	= os.getcwd() + '/'

	CHECKPOINT_PATH = os.getcwd()+'/tsmodel/checkpoints.kn/c-12.npz'

	RAM_DUMP_EXE_PATH = os.getcwd() + '\\dump\\DumpIt.exe'

	WELT_PATH = os.getcwd() + '\\WELT\\Tools'

	FILE_IMG_INFO 	= "Imageinfo.txt"
	FILE_WHOIS 		= "whois.txt"
	FILE_COM_INFO 	= "computer_info.txt"

	FILE_CMDLINE 	= "cmdline.txt"
	FILE_DLL_HASH 	= "dll_hash.csv"
	FILE_DLL_DUMP 	= "dlldump.txt"
	FILE_EXE_HASH 	= "exe_hash.csv"
	FILE_NETSCAN 	= "netscan.txt"
	FILE_PROCDUMP 	= "procdump.txt"
	FILE_PSTREE 	= "pstree.txt"

	FLDR_DLL		= "dlls\\"
	FLDR_EXE 		= "exesample\\"
	
	#file location for welt json file
	FLDR_WELT_JSON	= WELT_PATH+"\\EventLogOutput\\Analysis"
	
	FILE_WELT_JSON = FLDR_WELT_JSON + "\\Security_Analysis.json"


	# Choose which fields to extract
	FLDS_IMG_INFO = ["Suggested Profile(s)", "Image date and time"]

	FLD_COM_INFO = ["Name", "Manufacturer", "Model"]

	FLD_WHOIS = ["IP", "Organisation", "HostName", "ISP", "Continent", "Country", "State/Region", "City"]

	HEURISTICS_SUS = 5
	TS_SUS = 0.7

	def __init__(self):
		self.file_analyzer = staticanalysis.PEAnalyser()

	def start_triage_analysis(self, folder_path):
		# Extract Info

		if folder_path[-1] != "\\":
			folder_path += "\\"

		# return self.start_review_triage("C:\\Users\\User\\Desktop\\2202-WELTPEIOC-Suite\\GUI\\tmp\\triageResult.json")

		img_info_det = self.triage_parse_image_profiles(folder_path)
		img_com_det = self.triage_parse_image_computer_info(folder_path)
		img_dll_hashes = self.triage_parse_dlls_hashes(folder_path)
		img_exe_hashes = self.triage_parse_exe_hashes(folder_path)

		try:
			pst_res = self.triage_parse_pstree(folder_path)
		except:
			pst_res = "None"

		try:
			img_whois = self.triage_parse_whois(folder_path)
			for x in img_whois:
				for k in self.FLD_WHOIS:
					if k not in x:
						x[k] = "None"
					else:
						if x[k] == '':
							x[k] = "None"

			# img_whois = json.dumps(img_whois)
		except:
			img_whois = "None"


		
		try:
			mal_exes = self.triage_evaluate_malware(folder_path+self.FLDR_EXE, img_exe_hashes)
		except:
			mal_exes = "None"

		try:
			mal_dlls = self.triage_evaluate_malware(folder_path+self.FLDR_DLL, img_dll_hashes)
		except:
			mal_dlls = "None"

		
		mal_count = 0 	
		if mal_exes != "None":

			mal_count += sum(1 for x in mal_exes if x['Heuristics Indicators'] != "Error" and (int(x['Heuristics Indicators']) > self.HEURISTICS_SUS or float(x['Tensorflow Model']) > self.TS_SUS))
		if mal_dlls != "None": 
			mal_count += sum(1 for x in mal_dlls if x['Heuristics Indicators'] != "Error" and (int(x['Heuristics Indicators']) > self.HEURISTICS_SUS or float(x['Tensorflow Model']) > self.TS_SUS))


		try:
			print(self.FILE_WELT_JSON)
			if os.path.exists(self.FILE_WELT_JSON):
				os.remove(self.FILE_WELT_JSON)
			self.triage_analyze_security_log(folder_path+"Security.evtx") #This one idk u all want fixed or what
			evt_data = self.get_welt_json_data(self.FILE_WELT_JSON)
		except:
			evt_data = "None"

		triage_result = {
					"ImgName": str(img_com_det['Name']),
					"ImgDateTime": str(img_info_det['Image date and time']),
					"ImgModel": str(img_com_det['Model']),
					"ImgManufacturer":str(img_com_det['Manufacturer']),

					"ProcessesCount": str(self.triage_get_processes_count(folder_path)),
					"DomainsCount": str(len(img_whois)) if img_whois != "None" else img_whois,
					"MalignFileCount": str(mal_count), # Count based on how many dll's heursitics > 4 or 5 , and ts > 50%
					"FlaggedEvents": str(len(evt_data)),
					"PstreeResult": pst_res,
			
					"WhoIsDomainDetails": img_whois,
					"FilesAnalysisDetails": mal_exes,
					"DLLAnalysisDetails":mal_dlls,
					"EventLogAnalysisDetails": evt_data 

		}

		with open(os.getcwd()+"\\GUI\\tmp\\triageResult.json", 'w') as f:
			f.write(json.dumps(triage_result))
		
		return triage_result


	def triage_parse_image_profiles(self, a_folder):
		# Assuming in case folder the imageprofile file name is fixed.
		
		# Parse from  Imageinfo.txt
		ret_data = {}
		with open(a_folder+self.FILE_IMG_INFO, 'r') as f:
			buf = f.read()
			lines = buf.split('\n')
			for x in lines:
				row = x.strip().split(':', 1)
				if row[0].strip() in self.FLDS_IMG_INFO:
					ret_data[row[0].strip()] = row[1]
			f.close()

		return ret_data
		

	def triage_parse_image_computer_info(self, a_folder):
		# Parse from computer_info.txt
		ret_data = {}

		# print(a_folder+self.FILE_COM_INFO)
		with open(a_folder+self.FILE_COM_INFO, 'r') as f:
			buf = f.read().encode().decode('UTF-16')
			cleaned = re.sub(r'\n{2,}', '\n', buf)
			for l in cleaned.split('\n'):
				if ":" in l:
					x = l.split(":", 1)
					if x[0].strip() in self.FLD_COM_INFO:
						ret_data[x[0].rstrip()] = x[1]
		return ret_data

	def triage_parse_whois(self, a_folder):
		# Returns a list of dicts
		ret_data = []

		with open(a_folder+self.FILE_WHOIS, 'r') as f:
			buf = f.read()
			cleaned = re.sub(r'\n{2,}', '\n\n', buf)
			segments = cleaned.split("\n\n")
			for segment in segments:
				s_dict = {}
				if len(segment) != 0:					
					for line in segment.split('\n'):
						x = line.split(':',1)
						if x[0] in self.FLD_WHOIS:
							s_dict[x[0].strip()] = x[1].strip()
					ret_data.append(s_dict)
		return ret_data


	def triage_parse_csv_hash(self, a_folder, file_name):		
		data = {}
		with open(a_folder+file_name, 'r') as f:
			reader = csv.reader(f)
			# {"File":[md5,sha1]}
			data = {x[1]:[x[2],x[3]] for x in reader if len(x) != 0}
			return data

	def triage_parse_dlls_hashes(self, a_folder):
		return self.triage_parse_csv_hash(a_folder, self.FILE_DLL_HASH)
		
	def triage_parse_exe_hashes(self, a_folder):
		return self.triage_parse_csv_hash(a_folder, self.FILE_EXE_HASH)


	def triage_get_processes_count(self, a_folder):
		try:
			return sum(1 for line in open(a_folder+self.FILE_PSTREE, 'r')) - 2
		except:
			return 0

	def triage_evaluate_malware(self, a_folder, file_details):
		
		# file details will contain the name with two hashes
		temp_folder = "C:\\Users\\User\\Desktop\\27-10-2020_20-52-14_test\\exesample\\"
		print(a_folder)
		i = 0

		ret_data = []
		for f in os.listdir(a_folder): # remember change temp folder back to a_folder
			f_dict = defaultdict(bool)

			try:

				heuristics_details = self.file_analyzer.get_heuristics_dict(a_folder+f)
				heuristics_flag_count = sum(1 for x in heuristics_details.values() if x == 1 or x == True)
			except:
				heuristics_details = None

			try: 
				ml_data = self.file_analyzer.get_ml_data(a_folder+f)
				tp = [(x,y) for x,y in ml_data.items()]
				inference_net = test.InferenceNet(self.CHECKPOINT_PATH)
				inputs = inference_net.get_vectorized_row(tp)
				ts_score = str(inference_net.run(inputs))
			except:
				ts_score = None

			f_dict['File Name'] = f
			f_dict['MD5'] = file_details[f][0]
			f_dict['SHA1'] = file_details[f][1]
			f_dict["VirusTotal"] = vtapi.get_scan_ratio_from_hash(str(file_details[f][0]))
			f_dict["Heuristics Indicators"] = str(heuristics_flag_count) if heuristics_details is not None else "Error"
			f_dict["Tensorflow Model"] = ts_score if ts_score is not None else "Error"
			# f_dict["Ember Model"] = ember_score if ember_score is not None else "Error"

			ret_data.append(f_dict)
			i += 1

			if i % 2 == 0:
				print(f_dict)

		return ret_data
			
		# print(file_details['executable.1036'])


	def triage_analyze_security_log(self, file_path):
		# Call python module which feeds input to powershell
		# Returns output in a json format for JS to process		
		cmd = ["PowerShell", "-ExecutionPolicy", "Unrestricted", "-File", self.WELT_PATH+"\\Analysis.ps1" , file_path]
		# cmd = "PowerShell -ExecutionPolicy Unrestricted -File \"{}\" \"{}\"".format(self.WELT_PATH+"\\Analysis.ps1", file_path)

		print("CMD:", cmd)
		# sys.exit()
		ec = subprocess.call(cmd)


	def execute_ram_dump(self):
		status = subprocess.run(self.RAM_DUMP_EXE_PATH, shell=True)


	def get_welt_json_data(self, json_path):
		with open(json_path, 'r') as f:
			buf = f.read()
			M  = re.findall(r"\{.*?\}", buf, re.MULTILINE | re.DOTALL)
			ret_data = [json.loads(x) for x in M ]
			return ret_data
	

	def start_volatility_dump(self, case ,ram_dump):
		try:
			ioc.analysis(case,ram_dump)
			return 0
		except:
			return -1

	def triage_parse_pstree(self, a_folder):

		with open(a_folder+self.FILE_PSTREE, 'r') as f:
			lines = f.readlines()
			ret_data = []
			field_lengths = [len(x) for x in lines[1].split(' ')]
			for i, l in enumerate(lines[2:]):
				f_dict = {}
				f_dict['Name'] = str(l[0:51].strip())
				f_dict['PID'] = str(l[51:58].strip())
				f_dict['PPID'] = str(l[58:65].strip())
				f_dict['Threads'] = str(l[65:72].strip())
				f_dict['Handles'] = str(l[72:79].strip())
				f_dict['Time'] = str(l[79:].strip())

				ret_data.append(f_dict)

			return ret_data

	def start_malware_analyze(self, pe_path):

		res = staticanalysis.ResultsRetriever(pe_path)		

		try:
			res_imp = res.get_imported_results()
		except:
			res_imp = None


		try:
			res_sect = res.get_formated_section_details()
		except:
			res_sect = None


		try:
			heuristics_details = self.file_analyzer.get_heuristics_dict(pe_path)
			heuristics_flag_count = sum(1 for x in heuristics_details.values() if x == 1 or x == True)
		except:
			heuristics_details = None


		try: 
			ml_data = self.file_analyzer.get_ml_data(pe_path)
			tp = [(x,y) for x,y in ml_data.items()]
			inference_net = test.InferenceNet(self.CHECKPOINT_PATH)
			inputs = inference_net.get_vectorized_row(tp)
			ts_score = str(inference_net.run(inputs))
		except:
			ts_score = None


		ret_data = {
					"Heuristics":str(heuristics_flag_count) if heuristics_details is not None else "Error",
					"TensorModel":ts_score if ts_score is not None else "Error",
					"ImportsResult":res_imp if res_imp is not None  else "Error",
					"SectionResults":res_sect if res_sect is not None else "Error"
		}
		

		return ret_data


	def start_evt_analyze_one_log(self, log_path):


		ret_data = { "EventLogAnalysisSolo" : [] }
		try:
			print("Start: ", log_path)
			if os.path.exists(self.FILE_WELT_JSON):
				os.remove(self.FILE_WELT_JSON)				
			self.triage_analyze_security_log(log_path)
			evt_data = self.get_welt_json_data(self.FILE_WELT_JSON)
			print(evt_data)
			ret_data['EventLogAnalysisSolo'] = evt_data
		except:
			ret_data['EventLogAnalysisSolo'] = "Error"

		print("Done")
		print(ret_data)
		return ret_data


			# print(field_lengths)
	def start_review_triage(self, file_path):
		with open(file_path, 'r') as f:
			data = json.load(f)

		return data



if __name__ == '__main__':

	M = ModulesControler()
	M.start_evt_analyze_one_log("C:\\Users\\User\\Desktop\\2202-WELTPEIOC-Suite\\IOC\\09-01-2021_02-31-05_Patrick\\Security.evtx")

