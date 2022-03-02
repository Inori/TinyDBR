#include "memory_monitor.h"

 MemoryMonitor::MemoryMonitor(MonitorFlags flags) :
	m_flags(flags)
{
}

MemoryMonitor::~MemoryMonitor()
{
}

void MemoryMonitor::OnMemoryRead(void* address, size_t size)
{
}

// when size >= 16, value is the memory address
void MemoryMonitor::OnMemoryWrite(void* address, size_t size)
{
}