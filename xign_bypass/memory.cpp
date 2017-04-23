#include "memory.hpp"

namespace membase
{
	bool set_memory(unsigned char* address, void* data, unsigned int size)
	{
		MEMORY_BASIC_INFORMATION mbi;

		if (VirtualQuery(address, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
		{
			return false;
		}

		if (!mbi.Protect || (mbi.Protect & PAGE_GUARD))
		{
			return false;
		}
	
		unsigned long protection = 0;

		if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
		{
			if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &protection))
			{
				return false;
			}
		}

		memcpy(address, data, size);
		return (protection ? VirtualProtect(mbi.BaseAddress, mbi.RegionSize, protection, &protection) != FALSE : true);
	}
}

memory::memory(unsigned int target, unsigned int size)
{
	this->address =  reinterpret_cast<unsigned char*>(target);

	this->size = size;
	this->data.reset(new BYTE[this->size]);

	memcpy(this->data.get(), this->address, this->size);
}

memory::memory(unsigned char* target, unsigned int size)
{
	this->address = target;

	this->size = size;
	this->data.reset(new BYTE[this->size]);

	memcpy(this->data.get(), this->address, this->size);
}

memory::~memory(void)
{

}

bool memory::jump(void* destination)
{
	if (this->size < 5)
	{
		return false;
	}

	MEMORY_BASIC_INFORMATION mbi;

	if (VirtualQuery(this->address, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
	{
		return false;
	}

	if (!mbi.Protect || (mbi.Protect & PAGE_GUARD))
	{
		return false;
	}
	
	unsigned long protection = 0;

	if (!(mbi.Protect & PAGE_EXECUTE_READWRITE))
	{
		if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &protection))
		{
			return false;
		}
	}

	*reinterpret_cast<unsigned char*>(this->address) = 0xE9;
	*reinterpret_cast<unsigned int*>(this->address + 1) = this->get_distance(this->address, destination);

	unsigned int nops = this->size - 5;

	if (nops != 0)
	{
		memset(this->address + 5, 0x90, nops);
	}

	return (protection ? VirtualProtect(mbi.BaseAddress, mbi.RegionSize, protection, &protection) != FALSE : true);
}

inline unsigned int memory::get_distance(unsigned char* source, void* destination)
{
	return reinterpret_cast<unsigned int>(destination) - reinterpret_cast<unsigned int>(source) - 5;
}