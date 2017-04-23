#include "xigncode_manager.hpp"
#include "xigncode_callback.hpp"

#include <regex>
#include <string>

bool xigncode_manager::add_image(std::wstring wide_string)
{
	if (wide_string.empty())
		return false;
		
	std::wregex rgx(L"(.+) ([a-zA-Z\\.]+) => ([0-9a-fA-F]{8})");
	std::wsmatch matches;

	if (std::regex_search(wide_string, matches, rgx))
	{
		try
		{
			unsigned int image_start = std::stoul(matches[3].str(), 0, 16);

			if (PIMAGE_DOS_HEADER(image_start)->e_magic != IMAGE_DOS_SIGNATURE)
				return false;

			if (PIMAGE_NT_HEADERS(image_start + PIMAGE_DOS_HEADER(image_start)->e_lfanew)->Signature != IMAGE_NT_SIGNATURE)
				return false;
				
			unsigned int image_size = PIMAGE_NT_HEADERS(image_start + PIMAGE_DOS_HEADER(image_start)->e_lfanew)->OptionalHeader.SizeOfCode;

			wprintf(L"finding... %ws (%08X, %08X)\n", matches[2].str().c_str(), image_start, image_size);
			this->images.push_back({ matches[2].str(), image_start, image_size });
			return true;
		}
		catch (...)	
		{ 

		}
	}

	return false;
}

std::pair<unsigned int, unsigned int> xigncode_manager::get_memory_image(std::wstring image_name)
{
	if (!image_name.empty())
		for (memory_image& image : this->images)
			if (image.name.compare(image_name) == 0)
				return std::make_pair(image.start, image.size);

	return std::make_pair<unsigned int, unsigned int>(0, 0);
}

void xigncode_manager::set_hook(MEMORY_BASIC_INFORMATION& mbi, void** function_pointer, void* hook_function)
{
	unsigned long old_protect = 0;

	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &old_protect);
	function::redirect(true, function_pointer, hook_function);
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, old_protect, &old_protect);
}

void xigncode_manager::set_callback(MEMORY_BASIC_INFORMATION& mbi, void** function_pointer, void* callback_function)
{
	unsigned long old_protect = 0;

	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &old_protect);
	*function_pointer = callback_function;
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, old_protect, &old_protect);
}

xigncode_manager::xigncode_manager()
	: spider_ok(false)
{

}

void xigncode_manager::set_spider_ok(bool is_ok)
{
	this->spider_ok = is_ok;
}

bool xigncode_manager::is_spider_ok()
{
	return this->spider_ok;
}