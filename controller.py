import os
import re
import csv
import json
from collections import defaultdict
import subprocess
from IOC import ioc


# from pestaticanalyzer import staticanalysis
# from embermodel import predict
# from tsmodel import test,dataset

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

	def __init__(self):
		# self.file_analyzer = staticanalysis.PEAnalyser()
		# self.ember = predict.EmberUtility()
		# self._ts = 
		pass
		

	def start_triage_analysis(self, folder_path):
		# Extract Info
		
		if folder_path[-1] != "\\":
			folder_path += "\\"



		img_info_det = self.triage_parse_image_profiles(folder_path)
		img_com_det = self.triage_parse_image_computer_info(folder_path)

		img_dll_hashes = self.triage_parse_dlls_hashes(folder_path)
		img_exe_hashes = self.triage_parse_exe_hashes(folder_path)

		img_whois = self.triage_parse_whois(folder_path)

		mal_exes = self.triage_evaluate_malware(folder_path+self.FLDR_EXE, img_exe_hashes)
		mal_dlls = self.triage_evaluate_malware(folder_path+self.FLDR_DLL, img_dll_hashes)



		# print(img_whois)
		# print(img_dll_hash_det)
		# print(img_info_det)
		
		# print(img_com_det)

		# print(folder_path)

		triage_result = {
					"ImgName": img_com_det['Name'],
					"ImgDateTime": img_info_det['Image date and time'],
					"ImgModel": img_com_det['Model'],
					"ImgManufacturer":img_com_det['Manufacturer'],

					"ProcessesCount": 0,
					"DomainsCount": 0,
					"MalignFileCount": 0,
					"FlaggedEvents":0,

					# [defaultdict(None, {'IP': '56.139.105.26', 'ISP': '', 'Continent': 'North America', 'Country': 'United States'}), defaultdict(None, {'IP': '216.58.207.206', 'ISP': 'Google', 'Continent': 'North America', 'Country': 'United States', 'State/Region': 'California', 'City': 'Mountain View'}), defaultdict(None, {'IP': '56.27.91.26', 'ISP': '', 'Continent': 'North America', 'Country': 'United States'})]
					"WhoIsDomainDetails": img_whois,
					"FilesAnalysisDetails": mal_exes,
					"DLLAnalysisDetails":mal_dlls,
					"EventLogAnalysisDetails": []

		}

		print(triage_result)
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
				s_dict = defaultdict(None)
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



	def triage_evaluate_malware(self, a_folder, file_details):
		# file details will contain the name with two hashes
		temp_folder = "C:\\Users\\User\\Desktop\\27-10-2020_20-52-14_test\\exesample\\"
		print(a_folder)
		
		# print(file_details)
		ret_data = []
		for f in os.listdir(temp_folder): # remember change temp folder back to a_folder
			f_dict = defaultdict(bool)

			heuristics_details = self.file_analyzer.get_heuristics_dict(temp_folder+f)
			ml_data = self.file_analyzer.get_ml_data(temp_folder+f)

			tp = [(x,y) for x,y in ml_data.items()]

			inference_net = test.InferenceNet(self.CHECKPOINT_PATH)
			inputs = inference_net.get_vectorized_row(tp)
			ts_val = inference_net.run(inputs)
		
			heuristics_flag_count = sum(1 for x in heuristics_details.values() if x == 1 or x == True)

			f_dict['File Name'] = f
			f_dict['MD5'] = file_details[f][0]
			f_dict['SHA1'] = file_details[f][1]
			f_dict["VirusTotal"] = 0
			f_dict["Heuristics Indicators"] = str(heuristics_flag_count) + "/" + str(len(heuristics_details))
			f_dict["Ember Model"] = str(self.ember.predict_malware(temp_folder+f))
			f_dict["Tensorflow Model"] = ts_val

			ret_data.append(f_dict)

		return ret_data
			
		# print(file_details['executable.1036'])




	def triage_analyze_security_log(self, file_path):
		# Call python module which feeds input to powershell
		# Returns output in a json format for JS to process		
		cmd = ["PowerShell", "-ExecutionPolicy", "Unrestricted", "-File", self.WELT_PATH+"\\Analysis.ps1" , file_path ]  
		ec = subprocess.call(cmd)
		# 

	def triage_evaluate_exes_info(self):
		pass


	def execute_ram_dump(self):
		status = subprocess.run(self.RAM_DUMP_EXE_PATH, shell=True)


	def try_read_json(self):
		

		with open(self.FILE_WELT_JSON, 'r') as f:
			buf = f.read()
			
			# data = [x for x in buf.rsplit(r"\{.*\}")]
			for x in buf.rsplit(r"\{.*\}"):
				print(x)
			# print(data)

			# data = json.load(f)

		# print(data)
	
	def start_volatility_dump(self, case ,ram_dump):
		ioc.analysis(case,ram_dump)


if __name__ == '__main__':
	M = ModulesControler()

	# M.triage_analyze_security_log(os.getcwd()+"\\WELT\\Tools\\Security.evtx")

	M.try_read_json()
