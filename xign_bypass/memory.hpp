#pragma once

#include "generic.hpp"

#include <memory>

namespace membase
{
	bool set_memory(unsigned char* address, void* data, unsigned int size);
}

class memory
{
public:
	explicit memory(unsigned int target, unsigned int size);
	explicit memory(unsigned char* target, unsigned int size);
	~memory();

	bool jump(void* destination);

private:	
	unsigned int get_distance(unsigned char* source, void* destination);

	std::unique_ptr<unsigned char> data;
	unsigned char* address;
	unsigned int size;
};