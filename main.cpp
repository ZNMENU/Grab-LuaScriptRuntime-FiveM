HMODULE module = GetModuleHandle(L"ntdll.dll");

NTSTATUS(__stdcall* NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
NtQueryInformationThread = reinterpret_cast<decltype(NtQueryInformationThread)>(GetProcAddress(module, "NtQueryInformationThread"));
if (!NtQueryInformationThread)
{
	throw std::runtime_error("Failed to get NtQueryInformationThread");
}

// util::get_process_threads returns a std::vector<HANDLE> with every
// thread in the current process. Please create this yourself.
auto threads = util::get_process_threads();
if (threads.empty())
{
	throw std::runtime_error("Failed to get process threads");
}

struct THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
} tbi{ NULL };

// Grab the first thread in the process.
auto thread = threads.front();

THREADINFOCLASS ti = {};
if (!NT_SUCCESS(NtQueryInformationThread(thread, ti, &tbi, sizeof(tbi), nullptr)))
{
	// GetLastError?
	throw std::runtime_error("Failed to call NtQueryInformationThread");
}

// TEB is already defined in some header, but NT_TIB, ThreadLocalStoragePointer, etc.
// aren't included, so here's ours!
struct _TEB
{
	NT_TIB Tib;
	PVOID EnvironmentPointer;
	CLIENT_ID Cid;
	PVOID ActiveRpcInfo;
	PVOID ThreadLocalStoragePointer;
};

unsigned int tlsIdx = *(unsigned int*)((uint64_t)GetModuleHandle(L"adhesive.dll") + 0x1722710);

auto val = *(uint64_t*)(*((uint64_t*)((_TEB*)(tbi.TebBaseAddress))->ThreadLocalStoragePointer + (unsigned int)tlsIdx) + 0xA230);

// Close all the thread handles
for (auto& thread : threads)
{
	CloseHandle(thread);
}

if (val != 0xAFE287220C8335AEui64)
{
	auto y = val ^ 0xB8663FD607720057ui64;
	uint64_t v82 = __ROL8__(0x7FFFFF * _byteswap_uint64(y ^ __ROL8__(y, 3) ^ __ROL8__(y, 7)) + 0x21B7305B4385844i64, 48);
	uint64_t v83 = _byteswap_uint64(32769i64 * __ROL8__(v82 ^ (v82 >> 15), 51));
	uint64_t v84 = _byteswap_uint64((v83 - 0x7138C031A0F42923i64) ^ ((v83 - 0x7138C031A0F42923i64) >> 19));
	uint64_t v85 = _byteswap_uint64(524289 * _byteswap_uint64(v84 ^ (v84 << 11)));
	uint64_t v86 = (16 * (v85 & 0xF0F0F0F0F0F0F0Fi64)) | ((v85 & 0xF0F0F0F0F0F0F0F0ui64) >> 4);
	uint64_t v87 = ((v86 & 0xCCCCCCCCCCCCCCCCui64) >> 2) + 4 * (v86 & 0x3333333333333333i64);
	uint64_t v88 = ((v87 & 0xAAAAAAAAAAAAAAAAui64) >> 1) + 2 * (v87 & 0x5555555555555555i64);
	uint64_t v89 = _byteswap_uint64((v88 << 27) ^ v88 ^ 0xA84972DB02731B64ui64);
	uint64_t v90 = (16 * (v89 & 0xF0F0F0F0F0F0F0Fi64)) | ((v89 & 0xF0F0F0F0F0F0F0F0ui64) >> 4);
	uint64_t v91 = ((v90 & 0xCCCCCCCCCCCCCCCCui64) >> 2) + 4 * (v90 & 0x3333333333333333i64);
	uint64_t v92 = ((v91 & 0xAAAAAAAAAAAAAAAAui64) >> 1) + 2 * (v91 & 0x5555555555555555i64);
	uint64_t v93 = 0x86C1CD5C979B5FD5ui64 * (v92 ^ (v92 >> 31));

	return (script_runtime*)v93;
}
