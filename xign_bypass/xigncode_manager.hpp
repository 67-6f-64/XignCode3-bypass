#pragma once

#include "generic.hpp"

class xigncode_manager
{
public:
	static xigncode_manager& get_instance()
	{
		static xigncode_manager instance;
		return instance;
	}
			
	bool add_image(std::wstring wide_string);

	std::pair<unsigned int, unsigned int> get_memory_image(std::wstring image_name);
	
	void set_hook(MEMORY_BASIC_INFORMATION& mbi, void** function_pointer, void* hook_function);
	void set_callback(MEMORY_BASIC_INFORMATION& mbi, void** function_pointer, void* callback_function);

	void set_spider_ok(bool is_ok = true);
	bool is_spider_ok();

private:
	xigncode_manager();

	struct memory_image
	{
		std::wstring name;
		unsigned int start;
		unsigned int size;
	};

	std::vector<memory_image> images;
	bool spider_ok;
};