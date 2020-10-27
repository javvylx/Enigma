import os

class ModulesControler:

	RAM_DUMP_EXE_PATH = os.getcwd() + '\\dump\\DumpIt.exe'


	def __init__(self):
		
		# 
		pass

	


	def start_triage_analysis(self, folder_path):
		# Extract Info
		
		if folder_path[-1] != "\\":
			folder_path += "\\"




		print(folder_path)

		triage_result = {
					"ImgName": "",
					"ImgDateTime":"",
					"ImgModel":"",
					"ImgManufacturer":"",


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


	def triage_get_image_profiles(self):
		# Parse from  Imageinfo.txt
			
		pass

	def triage_get_image_computer_info(self):
		# Parse from computer_info.txt		
		pass



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

