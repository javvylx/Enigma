import os
import sys
import math
import re
from collections import defaultdict
from datetime import datetime

import pprint

try:
	import pefile
except ImportError:
	print("Unable to import pefile module")
	sys.exit()

try:
	import wincert.wintrust as wintrust
except ImportError:
	# If fail try pip install pythonforwindows
	print("Unable to import wintrust module")
	sys.exit()


SECT_CHAR_FLAGS = {
			'Has Code' :0x00000020, 
			'Initialized data' :0x00000040, 
			'Uninitialized data' :0x00000080, 
			'Cannot be cached' :0x04000000, 
			'Not pageable' :0x08000000, 
			'Shared' :0x10000000, 
			'Executable' :0x20000000, 
			'Readable' :0x40000000, 
			'Writable' :0x80000000	
}

class PEDetails:

	ATTRS_DOS_HDR 	= "e_magic, e_lfanew"
	ATTRS_FILE_HDR 	= "Machine, NumberOfSections, NumberOfSymbols, PointerToSymbolTable, SizeOfOptionalHeader, TimeDateStamp"
	ATTRS_OPP_HDR 	= "ImageBase, LoaderFlags, Magic, MajorImageVersion, MajorLinkerVersion, MajorOperatingSystemVersion, MajorSubsystemVersion, MinorImageVersion, MinorLinkerVersion, MinorOperatingSystemVersion, MinorSubsystemVersion, NumberOfRvaAndSizes, Reserved1, SectionAlignment, SizeOfCode, SizeOfHeaders, SizeOfHeapCommit, SizeOfHeapReserve, SizeOfImage, SizeOfInitializedData, SizeOfStackCommit, SizeOfStackReserve, SizeOfUninitializedData, Subsystem"
	ATTRS_SECTION 	= "Name, Misc_VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers"

	MAIN_ENCODING = "utf-8"
	def __init__(self, file_path, fast=True):
		"""Summary
		
		Args:
			file_path (TYPE): Description
			fast (bool, optional): Description
		"""
		self.file_path = file_path
		self.pe = pefile.PE(file_path)
	

	def _get_file_buffer(self):
		try:
			with open(self.file_path, "rb") as f:
				buf = f.read()
			return buf
		except Exception as e:
			return None

	def _get_file_size(self):
		# try:
		return os.path.getsize(self.file_path)
		# except Exception as e:
		# 	return None



	def _get_dos_header_attrs(self):
		"""Summary
		
		Returns:
			TYPE: Description
		"""
		# Returns important fields like e_magic and e_lfanew
		return {attr:getattr(self.pe.DOS_HEADER, attr) for attr in self.ATTRS_DOS_HDR.split(", ")}

	def _get_file_header_attrs(self):
		"""Summary
		
		Returns:
			TYPE: Description
		"""
		return {attr:getattr(self.pe.FILE_HEADER, attr) for attr in self.ATTRS_FILE_HDR.split(", ")}

	def _get_opp_header_attrs(self):
		"""Summary
		
		Returns:
			TYPE: Description
		"""
		return {attr:getattr(self.pe.OPTIONAL_HEADER, attr) for attr in self.ATTRS_OPP_HDR.split(", ")}
		
	def get_opptional_header_checksum(self):
		"""Summary
		
		Returns:
			TYPE: Description
		"""
		return self.pe.OPTIONAL_HEADER.CheckSum
	
	def recalculate_checksum(self):
		"""Summary
		
		Returns:
			TYPE: Description
		"""
		return self.pe.generate_checksum()
	
	def get_compile_time(self):
		try:
			return self.pe.FILE_HEADER.TimeDateStamp
		except Exception as e:
			return None

	def get_sections_details(self, char_type="Any"):
		"""Get details of interest from PE Sections
		
		Returns:
			dict: Name with entopy and characteristics
		
		Args:
			char_type (str, optional): Description
		
		Raises:
			e: Description
		"""
		try:
			if (char_type == "Any"):
				return [{attr:getattr(sect, attr) for attr in self.ATTRS_SECTION.split(", ")}for sect in self.pe.sections]
			else:
				return [{attr:getattr(sect, attr) for attr in self.ATTRS_SECTION.split(", ")}for sect in self.pe.sections if (sect.Characteristics & SECT_CHAR_FLAGS[char_type] == SECT_CHAR_FLAGS[char_type])]
		except Exception as e:
			return None


	
	
	def get_imported_details(self, decode=False):
		"""Summary
		
		Returns:
			TYPE: Description
		"""
		try: 
			if decode:
				return {entry.dll.decode('utf-8'):[api.name.decode('utf-8') for api in entry.imports] for entry in self.pe.DIRECTORY_ENTRY_IMPORT}
			else:
				return {entry.dll.decode('utf-8'):[api.name for api in entry.imports] for entry in self.pe.DIRECTORY_ENTRY_IMPORT}

		except AttributeError:
			return None
		# for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
		# 	for x in entry.imports:
	def get_imported_functions(self):
		try:
			apis = []
			for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
				for x in entry.imports:
					apis.append(x.name)
			return apis
		except Exception as e:
			return None
		

	def get_export_directory_details(self):
		try:
			return {export.address:export.name.decode('utf-8') for export in self.pe.DIRECTORY_ENTRY_EXPORT.symbols}
		except AttributeError:
			return None
	
	def get_debug_directory_details(self):

		try:
			for d in self.pe.DIRECTORY_ENTRY_DEBUG:
				print(d.entry)

		except Exception as e:
			return None

	def get_data_iat_rva(self):
		try:
			for x in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
				if x.name == "IMAGE_DIRECTORY_ENTRY_IMPORT":
					return x.VirtualAddress
		except Exception as e:
			return None
		return 0



	def get_opp_file_alignment(self):
		return self.pe.OPTIONAL_HEADER.FileAlignment
	
	def get_opp_size_of_stack_reserve(self):
		return self.pe.OPTIONAL_HEADER.SizeOfStackReserve

	def get_opp_size_of_stack_commit(self):
		return self.pe.OPTIONAL_HEADER.SizeOfStackCommit

	def get_opp_size_of_code(self):
		return self.pe.OPTIONAL_HEADER.SizeOfCode

	def get_opp_size_of_headers(self):
		return self.pe.OPTIONAL_HEADER.SizeOfHeaders

	def get_opp_image_base(self):
		return self.pe.OPTIONAL_HEADER.ImageBase

	def get_opp_min_os_ver(self):
		return self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion

	def get_opp_maj_os_ver(self):
		return self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion

	def get_opp_size_of_init_data(self):
		return self.pe.OPTIONAL_HEADER.SizeOfInitializedData

	def get_opp_size_of_uninit_data(self):
		return self.pe.OPTIONAL_HEADER.SizeOfUninitializedData




	def run(self):
		# print(self.pe.OPTIONAL_HEADER)
		# [for x in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY if x.name == "IMAGE_DIRECTORY_ENTRY_IMPORT"]
		# print(dir(self.pe))
		res = self.pe.dump_dict()
		# print(res.keys())

		print(res['DOS_HEADER'])

		print(self.pe.is_dll())
		print(self.pe.is_driver())

		print(self.pe.is_exe())

		print(self.pe.OPTIONAL_HEADER.Magic)
		print(len(self.pe.__data__))

		# for x in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
		# 	if x.name == "IMAGE_DIRECTORY_ENTRY_IMPORT":
		# 		print(x.VirtualAddress)

			# break
		
		# for x in self.pe.DIRECTORY_ENTRY_RESOURCE:
		# 	print(x)
		
		# print(dir(self.pe.DIRECTORY_ENTRY_IMPORT))


class EntropyAnalysis:
	
	ENTP_CLASSIFICATION = { 
				"HIGH_THLD_ENCRYPTED"	:lambda e: bool(e > 7.174),
				"LOW_THLD_ENCRYPTED"	:lambda e: bool(6.926 <= e <= 7.174),
				"HIGH_THLD_PACKED" 		:lambda e: bool(6.677 < e < 6.926),
				"LOW_THLD_PACKED"		:lambda e: bool(5.258 <= e <= 6.677),
				"HIGH_THLD_NATIVE" 		:lambda e: bool(4.941 < e < 5.258),
				"LOW_THLD_NATIVE" 		:lambda e: bool(4.629 <= e <= 4.941),
				"HIGH_THLD_PLAIN_TXT"	:lambda e: bool(4.066 < e < 4.629)
	}
	
	def __init__(self, pe_object: PEDetails):
		self.entropy_details = self._get_entropy_details(pe_object)

	@staticmethod
	def _evaluate_entropy(buff):
		i_array = [0 for _ in range(256)]

		db_entropy = 0.0; db_prob = 0.0
		for i in range(len(buff)):
			i_array[int(buff[i])] += 1

		for i in range(256):
			if i_array[i] != 0:
				db_prob = i_array[i] / len(buff)
				db_entropy -= db_prob * math.log(db_prob, 2)

		return db_entropy

	def _get_entropy_details(self, pe_object: PEDetails):

		buf = pe_object._get_file_buffer()
		if buf is not None:
			details = []
			try:
				details = [(sect['Name'].decode('utf-8').replace('\x00',''), round(EntropyAnalysis._evaluate_entropy(buf[sect['PointerToRawData']:sect['PointerToRawData']+sect['SizeOfRawData']]),4)) for sect in pe_object.get_sections_details()]
				details.insert(0,("#File", round(EntropyAnalysis._evaluate_entropy(buf),4)))
				return details
			except Exception as e:
				return None
		return None


	def get_all_entropy_details(self):
		return self.entropy_details
		
	def file_is_packed(self, confidence="Any"):
		return any(self.ENTP_CLASSIFICATION["HIGH_THLD_PACKED"](y) or self.ENTP_CLASSIFICATION["LOW_THLD_PACKED"](y) for x,y in self.entropy_details if x == "File")

	def file_is_encrypted(self, confidence="Any"):
		return any(self.ENTP_CLASSIFICATION["LOW_THLD_ENCRYPTED"](y) or self.ENTP_CLASSIFICATION["LOW_THLD_ENCRYPTED"](y) for x,y in self.entropy_details if x == "File")
		# print(self.entropy_details)
		
	def get_file_entropy(self):
		return [y for x,y in self.entropy_details if x == "#File"][0]

		

	def get_encrypted_sections(self, confidence="Any"):
		try:
			if confidence == "Any":
				return [n for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["HIGH_THLD_ENCRYPTED"](e) or self.ENTP_CLASSIFICATION["LOW_THLD_ENCRYPTED"](e))]
			elif confidence == "HIGH":
				return [n for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["HIGH_THLD_ENCRYPTED"](e))]
			elif  confidence == "LOW":
				return [n for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["LOW_THLD_ENCRYPTED"](e))]
		except Exception as e:
			return None

	def get_packed_sections(self, confidence="Any"):
		try:
			if confidence == "Any":
				return [n for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["HIGH_THLD_PACKED"](e) or self.ENTP_CLASSIFICATION["LOW_THLD_PACKED"](e))]
			elif confidence == "HIGH":
				return [n for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["HIGH_THLD_PACKED"](e))]
			elif  confidence == "LOW":
				return [n for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["LOW_THLD_PACKED"](e))]
		except Exception as e:
			return None

	def get_high_entropy_sections(self):
		return self.get_packed_sections("HIGH") + list(set(self.get_encrypted_sections("HIGH"))-set(self.get_packed_sections("HIGH")))
		

class HeuristicsAnalyser:

	NORMAL_ENTRY_SECTIONS = ['.text', '.code', 'CODE', 'INIT', 'PAGE']

	SIGNATURES = {
			"MZ" : b"\x4D\x5A", # will be at 0x0000
			"PE" : b"\x50\x45\x00\x00",  #will be at 0x00F8 & 0x100
			"OPP": [b"\x0B\x01", b"\x0B\x02", b"\x07\x01"] #will be at offset 0x110 & 0x118

	}

	SIG_OFFSETS = {
			"PE" : [0xF8, 0x100],
			"OPP": [0x110, 0x118]
	}

	ENC_PATH = os.getcwd()+"\\protector_section_names.txt"
	PKD_PATH = os.getcwd()+"\\packer_section_names.txt"


	def __init__(self, pe_object: PEDetails):
		self.score = 0
		self.pe_object = pe_object
		self.encrypt_sect_names = [line.rstrip("\n") for line in open(self.ENC_PATH,'r')]
		self.packer_sect_names = [line.rstrip("\n") for line in open(self.PKD_PATH,'r')]

	
	def find_pe_headers(self):
		mz_pos = -1 
		with open(self.pe_object.file_path, "rb") as f:
			buf = f.read()
			# print(self.SIGNATURES["MZ"])

		buffer_size = len(buf)
		found_coordinates = []
		for i in range(buffer_size):
			
			if (buf[i:i+2] == self.SIGNATURES["MZ"] and (i + 0x118) <= buffer_size):
				lfa_off = i+ 0x3c
				# print("Type: " ,type(buf[lfa_off:lfa_off+4]))
				p_e_lfanew = int.from_bytes(buf[lfa_off:lfa_off+4], byteorder='little')
				


				pe_off1 = i+self.SIG_OFFSETS["PE"][0]
				pe_off2 = i+self.SIG_OFFSETS["PE"][1]
				opp_off1 = i+self.SIG_OFFSETS["OPP"][0]
				opp_off2 = i+self.SIG_OFFSETS["OPP"][1]

				if p_e_lfanew != pe_off1 and p_e_lfanew != pe_off2:
					pass


				if (buf[pe_off1:pe_off1+4] == self.SIGNATURES["PE"] and buf[opp_off1:opp_off1+2] in self.SIGNATURES["OPP"]):
					found_coordinates.append({"MZ":i, "PE":pe_off1, "OPP":opp_off1})
				elif (buf[pe_off2:pe_off2+4] == self.SIGNATURES["PE"] and buf[opp_off2:opp_off2+2] in self.SIGNATURES["OPP"]):
					found_coordinates.append({"MZ":i, "PE":pe_off2, "OPP":opp_off2})
		return found_coordinates

	def get_num_of_pe_headers(self):
		return len(self.find_pe_headers())

	def has_multiple_pe_headers(self):
		return self.get_num_of_pe_headers() > 1

	
	def get_knonwn_packed_sections(self):
		return [s['Name'] for s in self.pe_object.get_sections_details() if s['Name'].decode('utf-8').rstrip("\x00") in self.packer_sect_names]



	def get_known_encrypted_sections(self):
		return [s['Name'] for s in self.pe_object.get_sections_details() if s['Name'].decode('utf-8').rstrip("\x00") in self.encrypt_sect_names]


	def has_known_packed_sections(self):
		return len(self.get_knonwn_packed_sections()) > 0

	def has_known_encrypted_sections(self):
		return len(self.get_known_encrypted_sections()) > 0

	def get_num_of_executable_sections(self):
		return len(self.pe_object.get_sections_details("Executable"))

	def has_multiple_executable_sections(self):
		return self.get_num_of_executable_sections() > 1

	def has_no_executable_sections(self):
		return self.get_num_of_executable_sections == 0


	def oep_section_details(self):
		""" Check which section or location
			Optional Header's EOP jumps to
		
		Args:
			pe_object (PEDetails): PEDetails object
		
		Returns:
			(int, str, int, int, int): Returns in (eop, SectName, SectionIndex, characteristics, entropy)
		"""
		buf = self.pe_object._get_file_buffer()
		name = ""; position = 0; entry = self.pe_object.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		for sect in self.pe_object.pe.sections:
			if (sect.VirtualAddress <= entry < (sect.VirtualAddress+sect.Misc_VirtualSize)):

				return (entry, sect.Name.decode("utf-8").replace("\x00", ""), position, sect.Characteristics, EntropyAnalysis._evaluate_entropy(buf[sect.PointerToRawData:sect.PointerToRawData+sect.SizeOfRawData]))
			else:
				position += 1
		return (entry, "Out", -1, 00000000,00000000)

	def oep_not_common_name(self):
		try:
			return self.oep_section_details()[1] not in self.NORMAL_ENTRY_SECTIONS
		except Exception as e:
			return None

	def oep_not_executable(self):
		try:
			return not self.oep_section_details()[3] & SECT_CHAR_FLAGS["Executable"] == SECT_CHAR_FLAGS["Executable"]
		except Exception as e:
			return None

	def oep_not_code(self):
		try:
			return not self.oep_section_details()[3] & SECT_CHAR_FLAGS["Has Code"] == SECT_CHAR_FLAGS["Has Code"]
		except Exception as e:
			return None

	def oep_not_in_any_sections(self):
		try:
			res = self.oep_section_details()
			return res[1] == "Out" and res[2] == -1
		except Exception as e:
			return None



	def section_is_executable(self, characteristics):
		try:
			return characteristics & SECT_CHAR_FLAGS["Executable"] == SECT_CHAR_FLAGS["Executable"]
		except Exception as e:
			return None

	def section_has_code(self, characteristics):
		try:
			return characteristics & SECT_CHAR_FLAGS["Has Code"] == SECT_CHAR_FLAGS["Has Code"]
		except Exception as e:
			return None

	def sections_with_no_raw_size(self):
		return [sect for sect in self.pe_object.pe.sections if sect.SizeOfRawData == 0]	

	def has_section_with_no_raw_size(self):
		return len(self.sections_with_no_raw_size()) > 0

	def has_section_executable_no_code(self):
		return any(self.section_is_executable(sect.Characteristics) and not self.section_has_code(sect.Characteristics) for sect in self.pe_object.pe.sections)

	def has_duplicated_section_names(self):
		section_names = [S['Name'].decode('utf-8').replace('\x00', '') for S in self.pe_object.get_sections_details()]
		return any(section_names.count(name) > 1 for name in section_names)

	def has_consistent_checksum(self):
		""" Evaluates if the recalculation checksum 
			is consistent with the checksum value 
			in optional header
		
		Returns:
			bool: True if recalcuated checksum is consistent
		
		Args:
			pe_object (PEDetails): Description
		"""
		return True if (self.pe_object.get_opptional_header_checksum() == self.pe_object.recalculate_checksum()) else False

	def has_consistent_size_of_code(self):
		""" Recalculates size of code and
			comepares with Optional header
			SizeOfCode value
		
		Args:
			pe_object (PEDetails): PEDetails object of executable
		
		Returns:
			TYPE: Description
		"""
		try:
			total_code  = sum(x["SizeOfRawData"] for x in self.pe_object.get_sections_details("Has Code"))
			return True if (self.pe_object._get_opp_header_attrs()["SizeOfCode"] == total_code) else False
		except Exception as e:
			return None

	def has_debug_directory(self):
		""" Malware usually do not have debug
			directory as it contains valueable
			information like time and date
		
		Args:
			pe_object (PEDetails): Description
		
		Returns:
			TYPE: Description
		"""
		return hasattr(self.pe_object.pe, "DIRECTORY_ENTRY_DEBUG")

	def has_import_directory(self):
		return hasattr(self.pe_object.pe, "DIRECTORY_ENTRY_IMPORT")		

	def has_export_directory(self):
		return hasattr(self.pe_object.pe, "DIRECTORY_ENTRY_EXPORT")	


	def get_resources_count(self):
		if not hasattr(self.pe_object.pe, "DIRECTORY_ENTRY_RESOURCE"):
			return 0
		else:
			return len(self.pe_object.pe.DIRECTORY_ENTRY_RESOURCE.entries)

	
	def sections_bigger_than_file(self):
		try:
			return sum(S['SizeOfRawData']for S in self.pe_object.get_sections_details()) > self.pe_object._get_file_size()
		except Exception as e:
			return None


class ImportsAnalyser:
	
	RULES_PATH = os.getcwd() + "\\import_rules.csv"

	def __init__(self):

		""" Parses the import rulesets  into a dict
			Format of the dict will be in this structure
			{API, [Severity, RegexPattern]}
		"""
		with open(self.RULES_PATH, 'r') as f:
			self.rules = {line.split(":")[0]:[x for x in line.split(":")[1:]] for line in f}

		# print(self.rules)
			
	def __len__(self):
		# Number of rulesets available
		return len(self.rules)

	def parse_imports(self, pe_object: PEDetails, min_severity=1):
		if pe_object:
			try:
				pe_imports = pe_object.get_imported_details(decode=True)
				found_apis = defaultdict(list)
				severity = 0
				count = 0
				for dll_name, func_names in pe_imports.items():
					for api, details in self.rules.items():
						if int(details[0]) >= min_severity:
							for func in func_names:
								if re.match(details[1], func):
									found_apis[str(api)].append(func)
									severity += int(details[0])
									count += 1
				return found_apis, severity, count
			except AttributeError:
				return None, None, None
		return None, None, None

	def get_flaged_functions(self, pe_object: PEDetails, min_severity=2):
		if pe_object:
			try:
				# a,b = self.parse_imports(pe_object)
				# print(a,b)
				pass
			except Exception as e:

				return None

		
		



class DataAnalyser:

	THLD_NORMAL 	= 3
	THLD_SUSPICIOUS = 10
	THLD_DANGEROUS 	= 13

	def __init__(self, pe_object):
		self.pe_object = pe_object

	def run_analysis(self):

		ent = EntropyAnalysis(self.pe_object)
		print(ent.get_all_entropy_details())

		heuristics = HeuristicsAnalyser(self.pe_object)
		# Reles to run and return to Browser to display
		heuristics_results  = {
					"is_digitally_signed" :wintrust.is_signed(self.pe_object.file_path), 
					"Total_sect_more_than_file": heuristics.sections_bigger_than_file(),
					"has_inconsistent_checksum": not heuristics.has_consistent_checksum(),
					"has_inconsistent_size_of_code": not heuristics.has_consistent_size_of_code(),
					"has_multiple_pe_header": heuristics.has_multiple_executable_sections(),
					"has_no_exec_sect": heuristics.has_no_executable_sections(),
					"has_duplicated_section_names": heuristics.has_duplicated_section_names(),
					"has_executable_section_without_code": heuristics.has_section_executable_no_code(),
					"has_no_import_directory": not heuristics.has_import_directory(),
					"has_no_export_directory": not heuristics.has_export_directory(),
					"has_no_debug_directory": not heuristics.has_debug_directory(),
					"OEP_not_code": heuristics.oep_not_code(),
					"OEP_uncommon_name": heuristics.oep_not_common_name(),
					"OEP_not_exec": heuristics.oep_not_executable(),
					"OEP_not_in_sections": heuristics.oep_not_in_any_sections()
		}


		import_rules = ImportsAnalyser()
		imp_apis, imp_score, sus_count = import_rules.parse_imports(self.pe_object)

		imports_results = {
					"has_anti_debug_api": 0,
					"has_vanilla_injection": 0,
					"has_keylogger_api": 0,
					"has_raw_socket_api": 0,
					"has_http_api": 0,
					"has_registry_api": 0,
					"has_process_creation_api": 0,
					"has_process_manipulation_api": 0,
					"has_service_manipulation_api": 0,
					"has_privilege_api": 0,
					"has_dacl_api": 0,
					"has_dynamic_import": 0,
					"has_packer_api": 0,
					"has_temporary_files": 0,
					"has_hdd_enumeration": 0,
					"has_driver_enumeration": 0,
					"has_eventlog_deletion": 0,
					"has_screenshot_api": 0,
					"has_audio_api": 0,
					"has_shutdown_functions": 0,
					"has_networking_api": 0,
					"has_password_dumping_api": 0,
					"has_object_manipulation_api": 0,
					"has_obfuscation_api": 0,
					"has_suspicious_system_api": 0,
		}



		# Set the dict values to 1 as long as it has the API
		if imp_apis is not None:
			for x,y in imp_apis.items():
				imports_results["has_"+x] = y
			
		pprint.pprint(heuristics_results)
		pprint.pprint(imports_results)


	def get_ml_data(self):
		"""This function is to use for getting data to be used for ML
		"""
		# row_headers = ["High_File_Entropy", "No_exec_sect", "OEP_not_code", "OEP_uncommon_name", "OEP_not_exec", "Total_sect_more_than_file", "No_import_directory", "No_export_directory", "No_debug_directory", "High_sect_entropy_count", "Sect_no_raw_Size_count", "Resources_count", "Writable_sects_count", "OEP_Sect_entropy", "PE_header_entropy", "Sus_to_non_sus_function_ratio", "has_anti_debug_api", "has_vanilla_injection", "has_keylogger_api", "has_raw_socket_api", "has_http_api", "has_registry_api", "has_process_creation_api", "has_process_manipulation_api", "has_service_manipulation_api", "has_privilege_api", "has_dacl_api", "has_dynamic_import", "has_packer_api", "has_temporary_files", "has_hdd_enumeration", "has_driver_enumeration", "has_eventlog_deletion", "has_screenshot_api", "has_audio_api", "has_shutdown_functions", "has_networking_api", "has_password_dumping_api", "has_object_manipulation_api", "has_obfuscation_api", "has_suspicious_system_api", "FileAlignment", "SizeOfStackReverse", "IsDLL", "SizeOfStackCommit", "The_ratio_of_malicious_API_calls_to_all_API_calls", "IAT_RVA", "OS_Maj_Version", "SizsOfCode", "SizeOfHeaders", "OS_min_Version", "ImageBase", "SizeOfInitializedData", "SizeOfUninitializedData"]
		ent = EntropyAnalysis(self.pe_object)
		heuristics = HeuristicsAnalyser(self.pe_object)
		import_rules = ImportsAnalyser()
		# import_rules.get_flaged_functions(self.pe_object)

		imp_apis, imp_score, sus_count = import_rules.parse_imports(self.pe_object)

		try:
			sus_ratio = float(sus_count/len(obj.get_imported_functions()))
		except Exception:
			sus_ratio = 0

		pe_headers_count = heuristics.get_num_of_pe_headers()

		CSV_FILE_INFO = {
		# "Ratio_malicious_API_calls_to_all_API_calls": 1,
					"File_Name":self.pe_object.file_path.split("\\")[-1],
					"High_File_Entropy": ent.file_is_packed() or ent.file_is_encrypted(),
					"Count_High_sect_entropy": len(ent.get_high_entropy_sections()),
					"Count_Sect_no_raw_Size": len(heuristics.sections_with_no_raw_size()),
					"Count_Writable_sects": len(self.pe_object.get_sections_details("Writable")),
					"Count_Resources": heuristics.get_resources_count(),
					"OEP_Sect_entropy": heuristics.oep_section_details()[4],
					"File_Entropy":ent.get_file_entropy(),
					"Opp_Magic":self.pe_object.pe.OPTIONAL_HEADER.Magic,
					"Count_PE_Headers":pe_headers_count,
					"OEP_not_in_sections": heuristics.oep_not_in_any_sections(),

					"is_digitally_signed" :wintrust.is_signed(self.pe_object.file_path), 
					"Total_sect_more_than_file": heuristics.sections_bigger_than_file(),
					"has_consistent_checksum": heuristics.has_consistent_checksum(),
					"has_consistent_size_of_code": heuristics.has_consistent_size_of_code(),
					"has_multiple_pe_header": pe_headers_count > 1,
					"has_no_exec_sect": heuristics.has_no_executable_sections(),
					"has_duplicated_section_names": heuristics.has_duplicated_section_names(),
					"has_executable_section_without_code": heuristics.has_section_executable_no_code(),
					"has_no_import_directory": not heuristics.has_import_directory(),
					"has_no_export_directory": not heuristics.has_export_directory(),
					"has_no_debug_directory": not heuristics.has_debug_directory(),
					"has_known_encrypted_sections": heuristics.has_known_encrypted_sections(),
					"has_known_packed_sections": heuristics.has_known_packed_sections(),
					"OEP_not_code": heuristics.oep_not_code(),
					"OEP_uncommon_name": heuristics.oep_not_common_name(),
					"OEP_not_exec": heuristics.oep_not_executable(),
					"Sus_to_non_sus_function_ratio": sus_ratio,
					"has_anti_debug_api": 0,
					"has_vanilla_injection": 0,
					"has_keylogger_api": 0,
					"has_raw_socket_api": 0,
					"has_http_api": 0,
					"has_registry_api": 0,
					"has_process_creation_api": 0,
					"has_process_manipulation_api": 0,
					"has_service_manipulation_api": 0,
					"has_privilege_api": 0,
					"has_dacl_api": 0,
					"has_dynamic_import": 0,
					"has_packer_api": 0,
					"has_temporary_files": 0,
					"has_hdd_enumeration": 0,
					"has_driver_enumeration": 0,
					"has_eventlog_deletion": 0,
					"has_screenshot_api": 0,
					"has_audio_api": 0,
					"has_shutdown_functions": 0,
					"has_networking_api": 0,
					"has_password_dumping_api": 0,
					"has_object_manipulation_api": 0,
					"has_obfuscation_api": 0,
					"has_suspicious_system_api": 0,
					"FileAlignment":  self.pe_object.get_opp_file_alignment(),
					"SizeOfStackReverse": self.pe_object.get_opp_size_of_stack_reserve(),
					"IsDLL": self.pe_object.pe.is_dll(),
					"SizeOfStackCommit": self.pe_object.get_opp_size_of_stack_commit(),					
					"IAT_RVA": self.pe_object.get_data_iat_rva(),
					"OS_Maj_Version": self.pe_object.get_opp_maj_os_ver(),
					"SizeOfCode": self.pe_object.get_opp_size_of_code(),
					"SizeOfHeaders": self.pe_object.get_opp_size_of_headers(),
					"OS_min_Version": self.pe_object.get_opp_min_os_ver(),
					"ImageBase": self.pe_object.get_opp_image_base(),
					"SizeOfInitializedData": self.pe_object.get_opp_size_of_init_data(),
					"SizeOfUninitializedData": self.pe_object.get_opp_size_of_uninit_data()
		}

		if imp_apis is not None:
			for a in imp_apis:
				CSV_FILE_INFO["has_"+a] = 1
			


		# Prints the nicely formatted dictionary
		return CSV_FILE_INFO

		# Sets 'pretty_dict_str' to the formatted string value
		# pretty_dict_str = pprint.pformat(dictionary)

if __name__ == '__main__':


	fp2 = "C:\\Windows\\System32\\AppVStreamMap.dll"

	file_path = "C:\\Users\\User\\Desktop\\123456.exe"
	obj = PEDetails(file_path)
	heu = HeuristicsAnalyser(obj)
	# print("Multiplpe:", heu.has_multiple_pe_headers())
	# obj.run()
	d = DataAnalyser(obj)
	print(d.get_ml_data())
	# ent = EntropyAnalysis(obj)
	
	# # obj.run()

	# heu = HeuristicsAnalyser(obj)
	# print(heu.has_multiple_pe_headers())

	# data_analyzer = DataAnalyser(obj)

	# data_analyzer.get_ml_data()
