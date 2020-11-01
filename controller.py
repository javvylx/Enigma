import os
import re
import csv
import json
import sys
from collections import defaultdict
import subprocess
from IOC import ioc

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



	HEURISTICS_SUS = 4
	TS_SUS = 0.5

	def __init__(self):
		self.file_analyzer = staticanalysis.PEAnalyser()



	def start_triage_analysis(self, folder_path):
		# Extract Info
		
		if folder_path[-1] != "\\":
			folder_path += "\\"

		with open(os.getcwd()+"\\GUI\\tmp\\triageResult.json", 'r') as f:
			data = json.load(f)

		print(data)

		return data

		# os.remove(self.FILE_WELT_JSON)
		# self.triage_analyze_security_log(folder_path+"Security.evtx") #This one idk u all want fixed or what
		# evt_data = self.get_welt_json_data(self.FILE_WELT_JSON)

		# print(evt_data)

		# with open("evtoutput.txt", 'w') as f:
		# 	f.write(json.dumps(evt_data))

		# sys.exit()

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


		# print(img_whois)
		# print(img_exe_hashes)
		# print("-------------")
		# print(img_dll_hashes)

		# sys.exit()
		 
		 
		
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
			mal_count += sum(1 for x in mal_exes if int(x['Heuristics Indicators']) > self.HEURISTICS_SUS or float(x['Tensorflow Model']) > self.TS_SUS)
		if mal_dlls != "None": 
			mal_count += sum(1 for x in mal_dlls if int(x['Heuristics Indicators']) > self.HEURISTICS_SUS or float(x['Tensorflow Model']) > self.TS_SUS)


		# try:
		print(self.FILE_WELT_JSON)
		
		if os.path.exists(self.FILE_WELT_JSON):
			os.remove(self.FILE_WELT_JSON)
		self.triage_analyze_security_log(folder_path+"Security.evtx") #This one idk u all want fixed or what
		evt_data = self.get_welt_json_data(self.FILE_WELT_JSON)
		# evt_data = json.dumps(evt_data)
		# except:
			# evt_data = "None"


		



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
					# [defaultdict(None, {'IP': '56.139.105.26', 'ISP': '', 'Continent': 'North America', 'Country': 'United States'}), defaultdict(None, {'IP': '216.58.207.206', 'ISP': 'Google', 'Continent': 'North America', 'Country': 'United States', 'State/Region': 'California', 'City': 'Mountain View'}), defaultdict(None, {'IP': '56.27.91.26', 'ISP': '', 'Continent': 'North America', 'Country': 'United States'})]
					"WhoIsDomainDetails": img_whois,
					"FilesAnalysisDetails": mal_exes,
					"DLLAnalysisDetails":mal_dlls,
					"EventLogAnalysisDetails": evt_data 

		}



		with open(os.getcwd()+"\\GUI\\tmp\\triageResult.json", 'w') as f:
			f.write(json.dumps(triage_result))
		
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
			return sum(1 for line in open(self.FILE_PSTREE, 'r')) - 2
		except:
			return 0

	def triage_evaluate_malware(self, a_folder, file_details):
		# file details will contain the name with two hashes
		temp_folder = "C:\\Users\\User\\Desktop\\27-10-2020_20-52-14_test\\exesample\\"
		print(a_folder)
		i = 0
		# print(file_details)
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
		cmd = ["PowerShell", "-ExecutionPolicy", "Unrestricted", "-File", self.WELT_PATH+"\\Analysis.ps1" , file_path ]  
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


	def start_evt_analyze_one_log(self, log_path):
		ret_data = { "EventLogAnalysisSolo" : [] }
		try:
			self.triage_analyze_security_log(log_path)
			evt_data = self.get_welt_json_data(self.FILE_WELT_JSON)
			ret_data['EventLogAnalysisSolo'] = evt_data
		except:
			ret_data['EventLogAnalysisSolo'] = "Error"
		finally:
			return ret_data


			# print(field_lengths)
	def start_review_triage(self, file_path):
		
		with open(file_path, 'r') as f:
			data = json.load(f)

		print(data)

		return data
	# def test_vtp(self):
	# 	print(vtapi.get_scan_ratio_from_hash("e2382a9cf3694eeadf8b3471c28593c8d3c03d5e"))




if __name__ == '__main__':
	M = ModulesControler()

	M.start_triage_analysis("C:\\Users\\User\\Desktop\\testdump")
	
	# with open(os.getcwd()+"\\GUI\\tmp\\triageResult.json", "r") as f:
	# 	data = json.loads(f.read())

	# 	print(data)


	# D = [{'name': '0x856076d0:csrss.exe', 'pid': '284', 'ppid': '276', 'thds': '9', 'hnds': '437', 'time': '2020-10-28 03:25:24 UTC+0000'}, {'name': '. 0x85031d28:conhost.exe', 'pid': '1828', 'ppid': '284', 'thds': '2', 'hnds': '33', 'time': '2020-10-27 11:25:41 UTC+0000'}, {'name': '0x85c95d28:wininit.exe', 'pid': '328', 'ppid': '276', 'thds': '3', 'hnds': '82', 'time': '2020-10-28 03:25:25 UTC+0000'}, {'name': '. 0x85cbf4e8:services.exe', 'pid': '416', 'ppid': '328', 'thds': '6', 'hnds': '210', 'time': '2020-10-28 03:25:26 UTC+0000'}, {'name': '.. 0x85eab0d8:taskhost.exe', 'pid': '1472', 'ppid': '416', 'thds': '9', 'hnds': '212', 'time': '2020-10-27 11:25:37 UTC+0000'}, {'name': '.. 0x85d3cd28:svchost.exe', 'pid': '648', 'ppid': '416', 'thds': '9', 'hnds': '252', 'time': '2020-10-27 11:25:32 UTC+0000'}, {'name': '.. 0x85d8cc70:svchost.exe', 'pid': '908', 'ppid': '416', 'thds': '5', 'hnds': '115', 'time': '2020-10-27 11:25:34 UTC+0000'}, {'name': '.. 0x85d67aa8:svchost.exe', 'pid': '776', 'ppid': '416', 'thds': '16', 'hnds': '398', 'time': '2020-10-27 11:25:33 UTC+0000'}, {'name': '... 0x85ec0c70:dwm.exe', 'pid': '1544', 'ppid': '776', 'thds': '3', 'hnds': '69', 'time': '2020-10-27 11:25:38 UTC+0000'}, {'name': '.. 0x85e414b0:cygrunsrv.exe', 'pid': '1556', 'ppid': '416', 'thds': '6', 'hnds': '101', 'time': '2020-10-27 11:25:38 UTC+0000'}, {'name': '... 0x84fb5398:cygrunsrv.exe', 'pid': '1808', 'ppid': '1556', 'thds': '0', 'hnds': '------', 'time': '2020-10-27 11:25:40 UTC+0000'}, {'name': '.... 0x85f4f1c0:sshd.exe', 'pid': '1868', 'ppid': '1808', 'thds': '4', 'hnds': '100', 'time': '2020-10-27 11:25:41 UTC+0000'}, {'name': '.. 0x85df0c18:spoolsv.exe', 'pid': '1176', 'ppid': '416', 'thds': '13', 'hnds': '276', 'time': '2020-10-27 11:25:36 UTC+0000'}, {'name': '.. 0x85fb1030:sppsvc.exe', 'pid': '796', 'ppid': '416', 'thds': '4', 'hnds': '166', 'time': '2020-10-27 11:25:43 UTC+0000'}, {'name': '.. 0x85d2a030:VBoxService.ex', 'pid': '584', 'ppid': '416', 'thds': '11', 'hnds': '118', 'time': '2020-10-28 03:25:31 UTC+0000'}, {'name': '.. 0x85fdf030:svchost.exe', 'pid': '1716', 'ppid': '416', 'thds': '5', 'hnds': '92', 'time': '2020-10-27 11:25:46 UTC+0000'}, {'name': '.. 0x85d7a6d8:svchost.exe', 'pid': '824', 'ppid': '416', 'thds': '30', 'hnds': '1067', 'time': '2020-10-27 11:25:33 UTC+0000'}, {'name': '... 0x85394030:wuauclt.exe', 'pid': '1196', 'ppid': '824', 'thds': '3', 'hnds': '88', 'time': '2020-10-27 11:30:58 UTC+0000'}, {'name': '.. 0x86048c38:SearchIndexer.', 'pid': '2292', 'ppid': '416', 'thds': '13', 'hnds': '638', 'time': '2020-10-27 11:25:59 UTC+0000'}, {'name': '... 0x88789418:SearchProtocol', 'pid': '1944', 'ppid': '2292', 'thds': '6', 'hnds': '316', 'time': '2020-10-27 12:48:38 UTC+0000'}, {'name': '... 0x8af09030:SearchFilterHo', 'pid': '1444', 'ppid': '2292', 'thds': '4', 'hnds': '104', 'time': '2020-10-27 12:48:39 UTC+0000'}, {'name': '.. 0x85d5f760:svchost.exe', 'pid': '736', 'ppid': '416', 'thds': '18', 'hnds': '458', 'time': '2020-10-27 11:25:33 UTC+0000'}, {'name': '.. 0x85e17970:svchost.exe', 'pid': '1220', 'ppid': '416', 'thds': '17', 'hnds': '314', 'time': '2020-10-27 11:25:36 UTC+0000'}, {'name': '.. 0x85db8338:svchost.exe', 'pid': '1036', 'ppid': '416', 'thds': '15', 'hnds': '483', 'time': '2020-10-27 11:25:34 UTC+0000'}, {'name': '.. 0x85e5e920:svchost.exe', 'pid': '1360', 'ppid': '416', 'thds': '11', 'hnds': '318', 'time': '2020-10-27 11:25:36 UTC+0000'}, {'name': '.. 0x85d6d030:svchost.exe', 'pid': '800', 'ppid': '416', 'thds': '29', 'hnds': '591', 'time': '2020-10-27 11:25:33 UTC+0000'}, {'name': '.. 0x85e61030:svchost.exe', 'pid': '1388', 'ppid': '416', 'thds': '23', 'hnds': '518', 'time': '2020-10-27 11:25:36 UTC+0000'}, {'name': '.. 0x8ae103c0:taskhost.exe', 'pid': '3936', 'ppid': '416', 'thds': '6', 'hnds': '290', 'time': '2020-10-27 11:40:40 UTC+0000'}, {'name': '.. 0x85f69d28:wlms.exe', 'pid': '1908', 'ppid': '416', 'thds': '4', 'hnds': '46', 'time': '2020-10-27 11:25:41 UTC+0000'}, {'name': '.. 0x860c8030:svchost.exe', 'pid': '3060', 'ppid': '416', 'thds': '14', 'hnds': '409', 'time': '2020-10-27 11:27:44 UTC+0000'}, {'name': '.. 0x85d1b9b8:svchost.exe', 'pid': '524', 'ppid': '416', 'thds': '9', 'hnds': '358', 'time': '2020-10-28 03:25:31 UTC+0000'}, {'name': '. 0x85cc5030:lsass.exe', 'pid': '424', 'ppid': '328', 'thds': '6', 'hnds': '594', 'time': '2020-10-28 03:25:26 UTC+0000'}, {'name': '. 0x85cc63c8:lsm.exe', 'pid': '432', 'ppid': '328', 'thds': '10', 'hnds': '147', 'time': '2020-10-28 03:25:26 UTC+0000'}, {'name': '0x84ed1b98:System', 'pid': '4', 'ppid': '0', 'thds': '87', 'hnds': '537', 'time': '2020-10-28 03:25:22 UTC+0000'}, {'name': '. 0x85041698:smss.exe', 'pid': '216', 'ppid': '4', 'thds': '2', 'hnds': '29', 'time': '2020-10-28 03:25:22 UTC+0000'}, {'name': '0x85ed2030:explorer.exe', 'pid': '1600', 'ppid': '1524', 'thds': '38', 'hnds': '1047', 'time': '2020-10-27 11:25:38 UTC+0000'}, {'name': '. 0x853dd8e0:DumpIt.exe', 'pid': '3360', 'ppid': '1600', 'thds': '1', 'hnds': '18', 'time': '2020-10-27 12:49:09 UTC+0000'}, {'name': '. 0x85fd9030:VBoxTray.exe', 'pid': '1804', 'ppid': '1600', 'thds': '12', 'hnds': '142', 'time': '2020-10-27 11:25:45 UTC+0000'}, {'name': '. 0x886bf758:BC14.exe', 'pid': '3676', 'ppid': '1600', 'thds': '1', 'hnds': '75', 'time': '2020-10-27 12:49:14 UTC+0000'}, {'name': '. 0x88697958:DumpIt.exe', 'pid': '1812', 'ppid': '1600', 'thds': '1', 'hnds': '19', 'time': '2020-10-27 12:49:23 UTC+0000'}, {'name': '0x85c8a500:csrss.exe', 'pid': '320', 'ppid': '312', 'thds': '8', 'hnds': '240', 'time': '2020-10-28 03:25:25 UTC+0000'}, {'name': '. 0x8640fa40:conhost.exe', 'pid': '2976', 'ppid': '320', 'thds': '2', 'hnds': '34', 'time': '2020-10-27 12:49:09 UTC+0000'}, {'name': '. 0x853b39b0:conhost.exe', 'pid': '540', 'ppid': '320', 'thds': '2', 'hnds': '34', 'time': '2020-10-27 12:49:23 UTC+0000'}, {'name': '0x85c8b8e8:winlogon.exe', 'pid': '352', 'ppid': '312', 'thds': '3', 'hnds': '110', 'time': '2020-10-28 03:25:25 UTC+0000'}]

	# ans = {str(y):1 for y in  [x.keys() for x in D]}
	# print(ans)
		
		

	
	# M.test_vtp()
	# print(M.triage_parse_pstree("C:\\Users\\User\\Desktop\\testdump\\"))

	# M.start_triage_analysis("C:\\Users\\User\\Desktop\\testdump")

	# pass

# 
	# M.triage_analyze_security_log(os.getcwd()+"\\WELT\\Tools\\Security.evtx")

	# M.get_welt_json_data()
