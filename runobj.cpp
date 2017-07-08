#pragma warning(disable : 4005)	// macro redefinition (in windows headers)
#pragma warning(disable : 4091)	// 'typedef ': ignored on left of '' when no variable is declared
#pragma warning(disable : 4996)	// 'fopen': This function or variable may be unsafe.

#include <coffi/coffi.hpp>
#include <unordered_map>
#include <string>

#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

using namespace COFFI;

typedef std::unordered_map<std::string, const char*> InSituSymbolMap;

const char* getSymbolAddressInCurrentProcess(const InSituSymbolMap& inSituMap, const std::string& name) {
	auto it = inSituMap.find(name);
	if (it != inSituMap.end()) {
		// Use the binary map by default so that if a symbol exists in the binary, we will use it
		return it->second;
	} else {
		// Otherwise fall back to DbgHelp. This may get us symbols in loaded DLLs, such as msvcrt.dll.
		// Those won't necessarily lie within a 32bit offset from our module, but we generate thunks
		// to call them with absolute addresses if needed.

		SYMBOL_INFO symbol;
		symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
		symbol.MaxNameLen = 1;

		if (SymFromName(GetCurrentProcess(), name.c_str(), &symbol)) {
			return (const char*)symbol.Address;
		} else {
			abort();
			return nullptr;
		}
	}
}

const char* makeFunctionThunk(const char* dstPtr)
{
	static char* lastAllocAddress = nullptr;
	char* targetAddress = lastAllocAddress;
	if (targetAddress) {
		targetAddress += 0x10000u;
	}
	else {
		// This is bork. Should find a sure way of allocating pages for sections
		targetAddress = (char*)((reinterpret_cast<size_t>(GetModuleHandle(nullptr)) & ~0xffffll) + 0x2000000u);
	}

	lastAllocAddress = (char*)VirtualAlloc(targetAddress, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	unsigned char* data = (unsigned char*)lastAllocAddress;

	// mov rax, dstPtr
	// jmp rax

	*data++ = 0x48;
	*data++ = 0xB8;
	*(const char**)data = dstPtr;
	data += 8;
	*data++ = 0xff;
	*data++ = 0xe0;

	DWORD oldProtect;
	VirtualProtect(lastAllocAddress, 32, PAGE_EXECUTE, &oldProtect);

	return lastAllocAddress;
}

InSituSymbolMap parseMapFile(const char* filePath)
{
	FILE* f = fopen(filePath, "rb");
	if (!f) abort();
	fseek(f, 0, SEEK_END);
	const long fileSize = ftell(f);
	fseek(f, 0, SEEK_SET);
	char *const fileContents = new char[fileSize];

	fread(fileContents, 1, fileSize, f);
	fclose(f);

	char* str = fileContents;

	auto skipLine = [&]() {
		while (*str++ != '\n') {}
	};

	for (int ln = 0; ln < 4; ++ln) {
		skipLine();
	}

	auto readHex = [&]() {
		size_t val = 0;
		for (int i = 0; i < 16; ++i) {
			val <<= 4;
			char ch = *str++;
			val += ch <= '9' ? (ch - '0') : (ch - 'a' + 10);
		}
		return val;
	};

	str += strlen(" Preferred load address is ");
	const size_t loadAddress = readHex();
	
	for (int ln = 0; ln < 3; ++ln) {
		skipLine();
	}

	// Skip to "  Address         Publics by Value              Rva+Base               Lib:Object"
	while (str[1] != ' ' || str[2] != 'A') skipLine();

	skipLine();
	skipLine();

	const char* const modBase = (const char*)GetModuleHandle(nullptr);
	InSituSymbolMap result;

	while (str < fileContents + fileSize) {
		str += 21;
		const char *const nameBegin = str;
		while (*str != ' ') { ++str; }
		const char* const nameEnd = str;

		while (*str == ' ') { ++str; }
		size_t addr = readHex();
		addr -= loadAddress;

		std::string name(nameBegin, nameEnd);
		result[name] = modBase + addr;

		skipLine();
	}

	delete[] fileContents;
	return result;
}

void relocateObj(coffi& c, const InSituSymbolMap& inSituMap)
{
	auto sections = c.get_sections();
	const size_t sectionCount = sections.size();

	std::unordered_map<std::string, symbol> symbolMap;
	for (auto& sym : c.symbols)
	{
		auto symName = c.string_to_name(sym.sym.name);
		symbolMap[symName] = sym.sym;
	}

	for (size_t sectionIdx = 0; sectionIdx < sectionCount; ++sectionIdx) {
		auto section = sections[unsigned(sectionIdx)];

		if (section->get_flags() & 0x20) {	// The section contains executable code.
			const auto& relocations = section->get_relocations();
			for (auto& rel : relocations) {
				if (rel.get_type() == 4) {	// The 32-bit relative address from the byte following the relocation
					auto& symbol = c.symbols[rel.header.symbol_table_index];
					auto symbolName = rel.get_symbol();

					auto fixup = [&](const char* dstAddr) {
						char* addrInSection = (char*)section->get_data() + rel.header.virtual_address;
						ptrdiff_t offset = dstAddr - (addrInSection + 4);
						if (int32_t(offset) != offset) {
							offset = makeFunctionThunk(dstAddr) - (addrInSection + 4);

							if (int32_t(offset) != offset) {
								abort();
							}
						}
						*(int32_t*)addrInSection = int32_t(offset);
					};

					if (2 == symbol.sym.storage_class) {	// IMAGE_SYM_CLASS_EXTERNAL_DEF
						fixup(getSymbolAddressInCurrentProcess(inSituMap, symbolName));
					}
					else if (3 == symbol.sym.storage_class) {	// IMAGE_SYM_CLASS_STATIC
						fixup(sections[symbol.sym.section_number - 1]->get_data() + symbol.sym.value);
					}
				}
			}

			DWORD oldProtect;
			VirtualProtect((void*)section->get_data(), section->get_data_size(), PAGE_EXECUTE, &oldProtect);
		}
	}
}

const void* getSymbolFromObj(coffi& c, const char* const name)
{
	for (auto& sym : c.symbols)
	{
		auto symName = c.string_to_name(sym.sym.name);
		if (symName == name) {
			const char* sectionData = c.get_sections()[sym.sym.section_number - 1]->get_data();
			return sectionData + sym.sym.value;
		}
	}

	return nullptr;
}

int main()
{
	const InSituSymbolMap inSituMap = parseMapFile("runobj.map");

	// Initialize DbgHelp and load symbols for all modules of the current process 
	SymInitialize(GetCurrentProcess(), nullptr, TRUE);

	coffi c;
	c.load("test.obj");
	relocateObj(c, inSituMap);

	auto foo = (int(*)(int, int))getSymbolFromObj(c, "foo");
	auto bar = (void(*)())getSymbolFromObj(c, "bar");
	auto baz = (int*(*)())getSymbolFromObj(c, "baz");

	int x = foo(2, 3);
	printf("foo returned %d\n", x);

	bar();
	
	int* z = baz();
	printf("baz returned a pointer at %d\n", *z);
	delete z;

	printf("Hit ENTER to exit.\n");
	getchar();

	return 0;
}
