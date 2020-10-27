import os
import re
import csv

class ModulesControler:

	RAM_DUMP_EXE_PATH = os.getcwd() + '\\dump\\DumpIt.exe'

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


	# Choose which fields to extract
	FLDS_IMG_INFO = ["Suggested Profile(s)", "Image date and time"]

	FLD_COM_INFO = ["Name", "Manufacturer", "Model", ]




	def __init__(self):
		
		# 
		pass

	def start_triage_analysis(self, folder_path):
		# Extract Info
		
		if folder_path[-1] != "\\":
			folder_path += "\\"



		img_info_det = self.triage_parse_image_profiles(folder_path)
		img_com_det = self.triage_parse_image_computer_info(folder_path)

		img_dll_hash_det = self.triage_parse_dlls_hashes(folder_path)
		print(img_dll_hash_det)
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
					"WhoIsDomainDetails": [],

					"EventLogAnalysisDetails": [],

					"FilesAnalysisDetails": [],

					"DLLAnalysisDetails":[]

		}



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


		    
		    # with open('coors_new.csv', mode='w') as outfile:
		    #     writer = csv.writer(outfile)
		    #     mydict = {rows[0]:rows[1] for rows in reader}


		# ret_data = {}
		# with open(a_folder+self.FILE_DLL_HASH, 'r') as f:
		# 	data = [l for l in f if l]
		# 	print(data)
			# buf = f.readline()
			# print(buf)


	def triage_analyze_security_log(self, file_path):
		# Call python module which feeds input to powershell
		# Returns output in a json format for JS to process		
		pass


	def triage_evaluate_exes_info(self):
		pass


	def execute_ram_dump(self):
		status = subprocess.run(self.RAM_DUMP_EXE_PATH, shell=True)



if __name__ == '__main__':
	M = ModulesControler()

	M.start_triage_analysis("C:\\Users\\User\\Desktop\\2202-WELTPEIOC-Suite\\ram_output")

