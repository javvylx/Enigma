import os
import sys
import math
import re
from collections import defaultdict
from datetime import datetime

import pprint

# try:
import pefile
# except ImportError:
# 	print("Unable to import pefile module")
# 	sys.exit()

# try:
from .wincert import wintrust
# import wincert.wintrust as wintrust
# except ImportError:
# 	# If fail try pip install pythonforwindows
# 	print("Unable to import wintrust module")
# 	sys.exit()


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
	ATTRS_SECTION 	= "Name, Misc_VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers, Characteristics"

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
		self.entropy_details, self.file_entropy = self._get_entropy_details(pe_object)

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
				# details.insert(0,("#File", round(EntropyAnalysis._evaluate_entropy(buf),4)))
				return details, round(EntropyAnalysis._evaluate_entropy(buf),4)
			except Exception as e:
				return None, None
		return None, None


	def get_all_entropy_details(self):
		return self.entropy_details
		
	def file_is_packed(self, confidence="Any"):
		return any(self.ENTP_CLASSIFICATION["HIGH_THLD_PACKED"](y) or self.ENTP_CLASSIFICATION["LOW_THLD_PACKED"](y) for x,y in self.entropy_details if x == "File")

	def file_is_encrypted(self, confidence="Any"):
		return any(self.ENTP_CLASSIFICATION["LOW_THLD_ENCRYPTED"](y) or self.ENTP_CLASSIFICATION["LOW_THLD_ENCRYPTED"](y) for x,y in self.entropy_details if x == "File")
		# print(self.entropy_details)
		
	def get_file_entropy(self):
		return self.file_entropy
		# return [y for x,y in self.entropy_details if x == "#File"][0]

		
	def get_sections_average_entropy(self):
		return sum(e for n,e in self.entropy_details if n != "#File")/(len(self.entropy_details)-1)

	def get_encrypted_sections(self, confidence="Any"):
		try:
			if confidence == "Any":
				return [(n,e) for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["HIGH_THLD_ENCRYPTED"](e) or self.ENTP_CLASSIFICATION["LOW_THLD_ENCRYPTED"](e))]
			elif confidence == "HIGH":
				return [(n,e) for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["HIGH_THLD_ENCRYPTED"](e))]
			elif  confidence == "LOW":
				return [(n,e) for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["LOW_THLD_ENCRYPTED"](e))]
		except Exception as e:
			return None

	def get_packed_sections(self, confidence="Any"):
		try:
			if confidence == "Any":
				return [(n,e) for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["HIGH_THLD_PACKED"](e) or self.ENTP_CLASSIFICATION["LOW_THLD_PACKED"](e))]
			elif confidence == "HIGH":
				return [(n,e) for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["HIGH_THLD_PACKED"](e))]
			elif  confidence == "LOW":
				return [(n,e) for n,e in self.entropy_details if (self.ENTP_CLASSIFICATION["LOW_THLD_PACKED"](e))]
		except Exception as e:
			return None

	def get_number_of_encrypted_sections(self, confidence="Any"):
		try:
			return len(self.get_encrypted_sections(confidence))
		except Exception as e:
			return None

	def get_number_of_packed_sections(self, confidence="Any"):
		try:
			return len(self.get_packed_sections(confidence))
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

	ENC_PATH = os.getcwd()+"\\pestaticanalyzer\\protector_section_names.txt"
	PKD_PATH = os.getcwd()+"\\pestaticanalyzer\\packer_section_names.txt"

	# ENC_PATH = os.getcwd()+"\\protector_section_names.txt"
	# PKD_PATH = os.getcwd()+"\\packer_section_names.txt"

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
				p_e_lfanew = i+int.from_bytes(buf[lfa_off:lfa_off+4], byteorder='little')
				


				pe_off1 = i+self.SIG_OFFSETS["PE"][0]
				pe_off2 = i+self.SIG_OFFSETS["PE"][1]
				opp_off1 = i+self.SIG_OFFSETS["OPP"][0]
				opp_off2 = i+self.SIG_OFFSETS["OPP"][1]

				# print (p_e_lfanew, pe_off1, pe_off2)
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
	
	RULES_PATH = os.getcwd() + "\\pestaticanalyzer\\import_rules.csv"
	# RULES_PATH = os.getcwd() + "\\import_rules.csv"



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

	# def parse_imports_for_table(self, pe_object: PEDetails, min_severity=1):
	# 	ret_data = []
	# 	if pe_object:
	# 		try:
	# 			print(self.rules.items())

	# 			pe_imports = pe_object.get_imported_details(decode=True)
	# 			# found_apis = defaultdict(list)
	# 			for dll_name, func_names in pe_imports.items():
	# 				for api, details in self.rules.items():
	# 					if int(details[0]) >= min_severity:
	# 						f_dict = defaultdict(str)
	# 						for func in func_names:
	# 							if re.match(details[1], func):
									
	# 								f_dict['API'] = api
	# 								f_dict['Severeness'] = details[0]
	# 								f_dict['Functions'] += func
	# 							ret_data.append(f_dict)

									
	# 			return ret_data
	# 		except AttributeError:
	# 			return None
		

	def get_flaged_functions(self, pe_object: PEDetails, min_severity=2):
		if pe_object:
			try:
				# a,b = self.parse_imports(pe_object)
				# print(a,b)
				pass
			except Exception as e:

				return None

		
		
class ResultsRetriever:

	SECTION_ATTRS =  ["Name", "VirtualAddress", "Misc_VirtualSize", "SizeOfRawData", "Characteristics"]
	def __init__(self, file_path):

		self.pe_object = PEDetails(file_path)
		self.ent = EntropyAnalysis(self.pe_object)
		self.heu = HeuristicsAnalyser(self.pe_object)

		self.imp = ImportsAnalyser()


	def _format(self,item):
		x = item
		if x[0] == "Name":
			x[1] = str(x[1]).replace("\\x00", "")
		else: 
			x[1] = hex(x[1])
		return x



	def get_formated_section_details(self):
		# For outputting to GUI table, 
		# Name, Entropy, VirtAddr,VirtSize,RawSize, Characteristics
		# 
		
		details = self.pe_object.get_sections_details()
		entropies = self.ent.get_all_entropy_details()

		ret_det = {"Headers": self.SECTION_ATTRS}
		ret_det['Rows'] = [{attr:str(x[attr]).replace('\\x00','').replace("\'", "").replace('b', '') for attr in self.SECTION_ATTRS} for x in details]

		for item in ret_det['Rows']:
			for e in entropies:
				if item['Name'] == e[0]:
					item['Entropy'] = e[1]
					break

		return ret_det
		
		# for x,y in ret_det['Rows']:

		# ret_det = {x for x,y in details.items()}
		# print(ret_det)
		# print(entropies)

	def get_imported_results(self):
		imp_apis, imp_score, sus_count = self.imp.parse_imports(self.pe_object, 1)
		return [{'API': x, 'Functions': ', '.join(z for z in y) } for x,y in imp_apis.items()]

class PEAnalyser:

	THLD_NORMAL 	= 3
	THLD_SUSPICIOUS = 10
	THLD_DANGEROUS 	= 13

	def __init__(self):
		# self.pe_object = pe_object
		self.imp_analyzer = ImportsAnalyser()

	def get_heuristics_dict(self, pe_file_path):

		pe_obj = PEDetails(pe_file_path)
		entropy_obj = EntropyAnalysis(pe_obj)
		heuristics_obj = HeuristicsAnalyser(pe_obj)
		imp_apis, imp_score, sus_count = self.imp_analyzer.parse_imports(pe_obj)

		# Reles to run and return to Browser to display
		heuristics_results  = {
					"is_not_digitally_signed" :not wintrust.is_signed(pe_obj.file_path), 
					"Total_sect_more_than_file": heuristics_obj.sections_bigger_than_file(),
					"has_inconsistent_checksum": not heuristics_obj.has_consistent_checksum(),
					"has_inconsistent_size_of_code": not heuristics_obj.has_consistent_size_of_code(),
					"has_multiple_pe_header": heuristics_obj.has_multiple_executable_sections(),
					"has_no_exec_sect": heuristics_obj.has_no_executable_sections(),
					"has_duplicated_section_names": heuristics_obj.has_duplicated_section_names(),
					"has_executable_section_without_code": heuristics_obj.has_section_executable_no_code(),
					"has_section_with_no_raw_size": len(heuristics_obj.sections_with_no_raw_size()) > 0,
					# "has_no_import_directory": not heuristics_obj.has_import_directory(),
					"has_no_export_directory": not heuristics_obj.has_export_directory(),
					"has_no_debug_directory": not heuristics_obj.has_debug_directory(),
					"OEP_not_code": heuristics_obj.oep_not_code(),
					"OEP_uncommon_name": heuristics_obj.oep_not_common_name(),
					"OEP_not_exec": heuristics_obj.oep_not_executable(),
					"OEP_not_in_sections": heuristics_obj.oep_not_in_any_sections(),
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
					"has_suspicious_system_api": 0
		}

		return heuristics_results
		
	def get_ml_data(self, pe_file_path):

		pe_obj = PEDetails(pe_file_path)
		entropy_obj = EntropyAnalysis(pe_obj)
		heuristics_obj = HeuristicsAnalyser(pe_obj)


		imp_apis, imp_score, sus_count = self.imp_analyzer.parse_imports(pe_obj)

		try:
			sus_ratio = float(sus_count/len(obj.get_imported_functions()))
		except Exception:
			sus_ratio = 0

		pe_headers_count = heuristics_obj.get_num_of_pe_headers()

		CSV_FILE_INFO = {
		# "Ratio_malicious_API_calls_to_all_API_calls": 1,
					"File_Name":pe_obj.file_path.split("\\")[-1],
					"High_File_Entropy": entropy_obj.file_is_packed() or entropy_obj.file_is_encrypted(),
					"Count_High_sect_entropy": len(entropy_obj.get_high_entropy_sections()),
					"Count_Sect_no_raw_Size": len(heuristics_obj.sections_with_no_raw_size()),
					"Count_Writable_sects": len(pe_obj.get_sections_details("Writable")),
					"Count_Resources": heuristics_obj.get_resources_count(),
					"OEP_Sect_entropy": heuristics_obj.oep_section_details()[4],
					"Sections_average_entropy": entropy_obj.get_sections_average_entropy(),
					"File_Entropy":entropy_obj.get_file_entropy(),
					"Opp_Magic":pe_obj.pe.OPTIONAL_HEADER.Magic,
					"Count_PE_Headers":pe_headers_count,
					"OEP_not_in_sections": heuristics_obj.oep_not_in_any_sections(),
					"Count_packed_sections_high":entropy_obj.get_number_of_packed_sections("HIGH"),
					"Count_encrypted_sections_high":entropy_obj.get_number_of_encrypted_sections("HIGH"),
					"Count_packed_sections_any":entropy_obj.get_number_of_packed_sections(),
					"Count_encrypted_sections_any":entropy_obj.get_number_of_encrypted_sections(),

					"is_digitally_signed" :wintrust.is_signed(pe_obj.file_path), 
					"Total_sect_more_than_file": heuristics_obj.sections_bigger_than_file(),
					"has_consistent_checksum": heuristics_obj.has_consistent_checksum(),
					"has_consistent_size_of_code": heuristics_obj.has_consistent_size_of_code(),
					"has_multiple_pe_header": pe_headers_count > 1,
					"has_no_exec_sect": heuristics_obj.has_no_executable_sections(),
					"has_duplicated_section_names": heuristics_obj.has_duplicated_section_names(),
					"has_executable_section_without_code": heuristics_obj.has_section_executable_no_code(),
					"has_no_import_directory": not heuristics_obj.has_import_directory(),
					"has_no_export_directory": not heuristics_obj.has_export_directory(),
					"has_no_debug_directory": not heuristics_obj.has_debug_directory(),
					"has_known_encrypted_sections": heuristics_obj.has_known_encrypted_sections(),
					"has_known_packed_sections": heuristics_obj.has_known_packed_sections(),
					"OEP_not_code": heuristics_obj.oep_not_code(),
					"OEP_uncommon_name": heuristics_obj.oep_not_common_name(),
					"OEP_not_exec": heuristics_obj.oep_not_executable(),
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
					"FileAlignment":  pe_obj.get_opp_file_alignment(),
					"SizeOfStackReverse": pe_obj.get_opp_size_of_stack_reserve(),
					"IsDLL": pe_obj.pe.is_dll(),
					"IsDriver": pe_obj.pe.is_driver(),
					"IsPe": pe_obj.pe.is_exe(),
					"SizeOfStackCommit": pe_obj.get_opp_size_of_stack_commit(),					
					"IAT_RVA": pe_obj.get_data_iat_rva(),
					"OS_Maj_Version": pe_obj.get_opp_maj_os_ver(),
					"SizeOfCode": pe_obj.get_opp_size_of_code(),
					"SizeOfHeaders": pe_obj.get_opp_size_of_headers(),
					"OS_min_Version": pe_obj.get_opp_min_os_ver(),
					"ImageBase": pe_obj.get_opp_image_base(),
					"SizeOfInitializedData": pe_obj.get_opp_size_of_init_data(),
					"SizeOfUninitializedData": pe_obj.get_opp_size_of_uninit_data()
		}

		return CSV_FILE_INFO



		# Sets 'pretty_dict_str' to the formatted string value
		# pretty_dict_str = pprint.pformat(dictionary)
if __name__ == '__main__':
	# print("hi")
	# dat = PEAnalyser()
	# print(dat.get_heuristics_dict("C:\\users\\user\\Desktop\\123456.exe"))
	A = ResultsRetriever("C:\\users\\user\\Desktop\\123456.exe")
	
	# obj = PEDetails("C:\\users\\user\\Desktop\\123456.exe")
	# 
	
