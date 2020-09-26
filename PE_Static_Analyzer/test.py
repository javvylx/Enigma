import pefile

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

	# Things to need
	# List whole PE header and field info
	# 
	ATTRS_DOS_HDR = "e_magic, e_lfanew"

	ATTRS_FILE_HDR = "Machine, NumberOfSections, NumberOfSymbols, PointerToSymbolTable, SizeOfOptionalHeader, TimeDateStamp"

	ATTRS_OPP_HDR = "ImageBase, LoaderFlags, Magic, MajorImageVersion, MajorLinkerVersion, MajorOperatingSystemVersion, MajorSubsystemVersion, MinorImageVersion, MinorLinkerVersion, MinorOperatingSystemVersion, MinorSubsystemVersion, NumberOfRvaAndSizes, Reserved1, SectionAlignment, SizeOfCode, SizeOfHeaders, SizeOfHeapCommit, SizeOfHeapReserve, SizeOfImage, SizeOfInitializedData, SizeOfStackCommit, SizeOfStackReserve, SizeOfUninitializedData, Subsystem"
	

	ATTRS_SECTION = "Misc_VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers"


	MAIN_ENCODING = "utf-8"

	def __init__(self, file_path):
		self.pe = pefile.PE(file_path)
		self.pe_header = {}

		
	def _get_dos_header_attrs(self):
		# Returns important fields like e_magic and e_lfanew
		return {attr:getattr(self.pe.DOS_HEADER, attr) for attr in self.ATTRS_DOS_HDR.split(", ")}

	def _get_file_header_attrs(self):
		return {attr:getattr(self.pe.FILE_HEADER, attr) for attr in self.ATTRS_FILE_HDR.split(", ")}

	def _get_opp_header_attrs(self):
		return {attr:getattr(self.pe.OPTIONAL_HEADER, attr) for attr in self.ATTRS_OPP_HDR.split(", ")}
		
	def get_opptional_header_checksum(self):
		return self.pe.OPTIONAL_HEADER.CheckSum
	
	def recalculate_checksum(self):
		return self.pe.generate_checksum()

				
	def get_section_details(self, char_type="Any"):
		""" Get details of interest from PE Sections
		
		Returns:
			dict: Name with entopy and characteristics
		"""
		try:
			if (char_type == "Any"):
				return {sect.Name.decode(self.MAIN_ENCODING).rstrip('\x00'):{attr:getattr(sect, attr) for attr in self.ATTRS_SECTION.split(", ")}for sect in self.pe.sections}
			else:
				return {sect.Name.decode(self.MAIN_ENCODING).rstrip('\x00'):{attr:getattr(sect, attr) for attr in self.ATTRS_SECTION.split(", ")}for sect in self.pe.sections if (sect.Characteristics & SECT_CHAR_FLAGS[char_type] == SECT_CHAR_FLAGS[char_type])}
		except Exception as e:
			raise e



	def _get_resources(self):
		resources = []

		if hasattr(self.pe, "DIRECTORY_ENTRY_RESOURCE"):
			for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
				try:
					resource = {}

					if resource_type.name is not None:
						name = str(resource_type.name)
					else:
						name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))

					if hasattr(resource_type, "directory"):
						for resource_id in resource_type.directory.entries:
							if hasattr(resource_id, "directory"):
								for resource_lang in resource_id.directory.entries:
									data = self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
									filetype = self._get_filetype(data)
									language = pefile.LANG.get(resource_lang.data.lang, None)
									sublanguage = pefile.get_sublang_name_for_lang(resource_lang.data.lang, resource_lang.data.sublang)

									resource["name"] = name
									resource["offset"] = "0x{0:08x}".format(resource_lang.data.struct.OffsetToData)
									resource["size"] = "0x{0:08x}".format(resource_lang.data.struct.Size)
									resource["filetype"] = filetype
									resource["language"] = language
									resource["sublanguage"] = sublanguage
									resources.append(resource)
				except:
					continue

		return resources

	
	
	def get_imported_details(self):
		
		imports = []
		for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []):
			try:
				symbols = []
				for imported_symbol in entry.imports:
					symbols.append({"address": hex(imported_symbol.address),"name": imported_symbol.name})
					imports.append({"dll": entry.dll.decode(self.MAIN_ENCODING),"imports": symbols})
			except:

				print("Unable to parse imported symbols.")

		return imports

	def run(self):
		pass
		
class HeuristicsAnalyser:
	@staticmethod
	def has_multiple_pe_header(pe_object: PEDetails):
		pass

	@staticmethod
	def verify_checksum(pe_object: PEDetails):
		""" Evaluates if the recalculation checksum 
			is consistent with the checksum value 
			in optional header
		
		Returns:
		    bool: True if recalcuated checksum is consistent
		"""
		return True if (pe_object.get_opptional_header_checksum() == pe_object.recalculate_checksum()) else False

	@staticmethod
	def invalid_section_of_execution(pe_object: PEDetails):
		pass

	@staticmethod
	def has_inconsistent_size_of_code(pe_object: PEDetails):

		code_sections = pe_object.get_section_details(char_type="Has Code")
		executable_sections = pe_object.get_section_details(char_type="Executable")
		print(executable_sections)
		# print(pe_object.get_section_details()[".text"])
		size = pe_object._get_opp_header_attrs()["SizeOfCode"]
		print(size)



	@staticmethod
	def has_multiple_executable_sections(pe_object: PEDetails):
		pass


if __name__ == '__main__':
	obj = PEDetails("c:\\users\\user\\desktop\\1234.exe")
	# print(obj._get_opp_header_attrs())
	# print(obj.run())
	HeuristicsAnalyser.has_inconsistent_size_of_code(obj)


	# print(obj.get_section_details())