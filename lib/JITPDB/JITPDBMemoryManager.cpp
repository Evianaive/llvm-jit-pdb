// license [
// This file is part of the LLVMJITPDB project. Copyright 2020 Vivien Millet.
// Distributed under the Apache License 2.0. Text available here at
// https://github.com/vlmillet/llvmjitpdb
// ]

#include <llvm/JITPDB/JITPDBMemoryManager.h>

#pragma warning(push, 0)
#include <llvm/Object/COFF.h>
#include <llvm/Support/FileSystem.h>
#pragma warning(pop)
#include <windows.h>
#include <algorithm>
#include <vector>

namespace {
enum class LogKind { Information, Warning, Error };
}

#define LLVM_JIT_PDB_LOG(Kind, ...)                                            \
  if (LogKind::Kind == LogKind::Warning || LogKind::Kind == LogKind::Error ||  \
      Verbose) {                                                               \
    printf(#Kind ": " __VA_ARGS__);                                            \
    printf("\n");                                                              \
  }

extern char JITPDB_HCK[];
extern char JITPDB_DLL[];
extern unsigned long long JITPDB_DLL_SIZE;

struct UNWIND_CODE {
  uint8_t OffsetInProlog;
  uint8_t UnwindOpCode : 4;
  uint8_t OpInfo : 4;
};

struct UNWIND_INFO {
  uint8_t Version : 3;
  uint8_t Flags : 5;
  uint8_t SizeOfProlog;
  uint8_t CountOfUnwindCodes;
  uint8_t FrameRegister : 4;
  uint8_t FrameRegisterOffset : 4;
  UNWIND_CODE UnwindCodeArray[256];
} uw;

namespace llvm {
namespace {
const char *SectionNames[4] = {".text", ".rdata", ".pdata", ".xdata"};
uint32_t alignUpU32(uint32_t Value, uint32_t Align) {
  if (Align == 0)
    return Value;
  return (Value + Align - 1) / Align * Align;
}

size_t computeDefaultEmbeddedTextSize() {
  auto ReadU16 = [](const char *Data, size_t Offset) -> uint16_t {
    uint16_t Value = 0;
    memcpy(&Value, Data + Offset, sizeof(Value));
    return Value;
  };
  auto ReadU32 = [](const char *Data, size_t Offset) -> uint32_t {
    uint32_t Value = 0;
    memcpy(&Value, Data + Offset, sizeof(Value));
    return Value;
  };

  const uint32_t PeOffset = ReadU32(JITPDB_DLL, 0x3C);
  const uint32_t OptionalOffset = PeOffset + 4 + 20;
  const uint16_t OptionalMagic = ReadU16(JITPDB_DLL, OptionalOffset);
  (void)OptionalMagic;

  const uint32_t SectionAlignment = ReadU32(JITPDB_DLL, OptionalOffset + 32);
  const uint32_t FileAlignment = ReadU32(JITPDB_DLL, OptionalOffset + 36);

  // Minimum viable layout:
  // - Total memory must keep Code/RData/RWData split (1/2, 1/4, 1/4).
  // - CodeSection.mem.size must satisfy %128 == 0.
  // => text size must be divisible by 256.
  const uint32_t MinByLayout = 8 * 1024;
  uint32_t MinText = MinByLayout;
  MinText = alignUpU32(MinText, std::max<uint32_t>(1, FileAlignment));
  MinText = alignUpU32(MinText, std::max<uint32_t>(1, SectionAlignment));
  return MinText;
}

int acquireCryptHandle(HCRYPTPROV &handle) {
  if (::CryptAcquireContextW(&handle, 0, 0, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return 0;

  int errval = ::GetLastError();
  if (errval != NTE_BAD_KEYSET)
    return errval;

  if (::CryptAcquireContextW(&handle, 0, 0, PROV_RSA_FULL,
                             CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT |
                                 CRYPT_SILENT))
    return 0;

  errval = ::GetLastError();
  // Another thread could have attempted to create the keyset at the same time.
  if (errval != NTE_EXISTS)
    return errval;

  if (::CryptAcquireContextW(&handle, 0, 0, PROV_RSA_FULL,
                             CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    return 0;

  return ::GetLastError();
}
bool osCrypt(void *buf, std::size_t len) {
  HCRYPTPROV handle;
  int errval = acquireCryptHandle(handle);

  if (!errval) {
    BOOL gen_ok =
        ::CryptGenRandom(handle, (DWORD)len, static_cast<unsigned char *>(buf));
    if (!gen_ok)
      errval = ::GetLastError();
    ::CryptReleaseContext(handle, 0);
  }

  if (!errval)
    return true;

  return false;
}
uint64_t randInteger() {
  char ran[] = "123456789abcdef";

  assert(sizeof(ran) == 16);
  const int max_nibbles = sizeof(ran);

  int nibbles_used = max_nibbles;

  uint64_t result = 0;
  for (uint32_t i = 0; i < sizeof(uint64_t) * 2; ++i) {
    if (nibbles_used == max_nibbles) {
      if (!osCrypt(ran, sizeof(ran)))
        return 0;
      nibbles_used = 0;
    }
    int c = ran[nibbles_used / 2];
    c >>= 4 * (nibbles_used++ & 1);
    result |= uint64_t(c & 0xf) << (i * 4);
  }

  return result;
}

std::string guidToStr(codeview::GUID const &guid) {
  static const char *Lookup = "0123456789ABCDEF";
  std::string res;
  for (int i = 0; i < 16;) {
    uint8_t Byte = guid.Guid[i];
    uint8_t HighNibble = (Byte >> 4) & 0xF;
    uint8_t LowNibble = Byte & 0xF;
    res += Lookup[HighNibble];
    res += Lookup[LowNibble];
    ++i;
    if (i >= 4 && i <= 10 && i % 2 == 0)
      res += '-';
  }
  return std::move(res);
}

} // namespace
JITPDBMemoryManager::JITPDBMemoryManager(
    StringRef PdbOutputPath, StringRef PdbTemplatePath,
    std::function<void(void *)> NotifyModuleEmittedCB)
    : JITPDBMemoryManager(PdbOutputPath, PdbTemplatePath,
                          NotifyModuleEmittedCB, 0, 0) {}

JITPDBMemoryManager::JITPDBMemoryManager(
    StringRef PdbOutputPath, StringRef PdbTemplatePath,
    std::function<void(void *)> NotifyModuleEmittedCB,
    size_t RequestedCodeSize, size_t RequestedDataSize)
    : PdbPath(PdbOutputPath), NotifyModuleEmitted(NotifyModuleEmittedCB),
      PdbTplPath(PdbTemplatePath) {
  // auto& NextGUID = getNextBuildGuid();
#define PDB_GUID_TEST 0
#if PDB_GUID_TEST
  uint64_t lo = 0x0123456789ABCDEF;
  uint64_t hi = 0xFEDCBA9876543210;
#else
  uint64_t lo = randInteger();
  uint64_t hi = randInteger();
#endif
  memcpy(Guid.Guid, &lo, sizeof(lo));
  memcpy(&Guid.Guid[8], &hi, sizeof(hi));

  auto lastSlash = this->PdbPath.find_last_of("\\/");
  PdbName = PdbPath;
  OutputPath = ".";
  if (lastSlash != StringRef::npos) {
    OutputPath = PdbPath.substr(0, lastSlash);
    PdbName = PdbPath.substr(lastSlash + 1);
  }
  sys::fs::create_directories(OutputPath);

  DllPath = PdbPath.substr(0, PdbPath.find_last_of('.'));
  DllPath += ".dll";

  if (PdbTplPath.empty()) {
    memcpy(&DllHackInfoData, JITPDB_HCK, sizeof(DllHackInfo));
    if (RequestedCodeSize == 0 && RequestedDataSize == 0) {
      size_t MinText = computeDefaultEmbeddedTextSize();
      RequestedCodeSize = MinText / 2;
      RequestedDataSize = MinText / 2;
    }
    buildRuntimeTemplateFromEmbedded(RequestedCodeSize, RequestedDataSize);
  } else {
    DllTplPath = PdbTplPath.substr(0, PdbTplPath.find_last_of('.'));
    DllTplPath += ".dll";
    auto HckFilePath = PdbTplPath.substr(0, PdbTplPath.find_last_of('.'));
    HckFilePath += ".hck";
    FILE *hckFD = fopen(HckFilePath.c_str(), "rb");
    if (!hckFD) {
      LLVM_JIT_PDB_LOG(Error, "missing %s file", HckFilePath.c_str());
      return;
    }
    fread(&DllHackInfoData, 1, sizeof(DllHackInfo), hckFD);
    fclose(hckFD);
  }

  // read hack inf (generated .cpp file contains the data related to dll/pdb
  // hacking offsets)

  // we use only the backing dll .text section for storing code+dataR+dataRW
  MemorySize = DllHackInfoData.SectionInfos[DllHackInfo::TEXT].Size;

  createDll();
  loadDll();

  MemoryStart = (uint8_t *)(DllBaseAddress) +
                DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress;
  CodeSection.mem.addr = MemoryStart;
  CodeSection.mem.size = MemorySize / 2;
  CodeSection.cur = CodeSection.mem.addr;
  assert((CodeSection.mem.size % 128) == 0);
  DataRSection.mem.addr = CodeSection.mem.addr + CodeSection.mem.size;
  DataRSection.mem.size = MemorySize / 4;
  DataRSection.cur = DataRSection.mem.addr;
  DataRWSection.mem.addr = DataRSection.mem.addr + DataRSection.mem.size;
  DataRWSection.mem.size = MemorySize / 4;
  DataRWSection.cur = DataRWSection.mem.addr;
}

JITPDBMemoryManager::~JITPDBMemoryManager() {
  unloadDll();
  // --destroyDll();-- => don't destroy dll for profiling purpose
}

void JITPDBMemoryManager::createDll() {
  FILE *DllFile = NULL;
  int remainingTries = 10;
  while (remainingTries--) {
#pragma warning(push, 0)
    if ((DllFile = fopen(DllPath.c_str(), "wb")))
#pragma warning(pop)
    {
      if (DllTplPath.empty()) {
        if (RuntimeDllTemplateData.empty()) {
          fwrite(JITPDB_DLL, JITPDB_DLL_SIZE, 1, DllFile);
        } else {
          fwrite(RuntimeDllTemplateData.data(), 1, RuntimeDllTemplateData.size(),
                 DllFile);
        }
      } else {
        FILE *DllTplFile = fopen(DllTplPath.c_str(), "rb");
        if (DllTplFile == nullptr) {
          LLVM_JIT_PDB_LOG(Error, "cannot find %s", DllTplPath.c_str());
          return;
        }
        fseek(DllTplFile, 0, SEEK_END);
        size_t S = ftell(DllTplFile);
        rewind(DllTplFile);
        void *M = malloc(S);
        fread(M, 1, S, DllTplFile);
        fwrite(M, 1, S, DllFile);
        fclose(DllTplFile);
      }
      fclose(DllFile);

      break;
    }
  }
}

bool JITPDBMemoryManager::buildRuntimeTemplateFromEmbedded(
    size_t RequestedCodeSize, size_t RequestedDataSize) {
  auto ReadU16 = [](const std::vector<char> &Data, size_t Offset) -> uint16_t {
    uint16_t Value = 0;
    memcpy(&Value, Data.data() + Offset, sizeof(Value));
    return Value;
  };
  auto ReadU32 = [](const std::vector<char> &Data, size_t Offset) -> uint32_t {
    uint32_t Value = 0;
    memcpy(&Value, Data.data() + Offset, sizeof(Value));
    return Value;
  };
  auto WriteU32 = [](std::vector<char> &Data, size_t Offset, uint32_t Value) {
    memcpy(Data.data() + Offset, &Value, sizeof(Value));
  };
  auto AlignUp = [](uint32_t Value, uint32_t Align) -> uint32_t {
    return alignUpU32(Value, Align);
  };

  RuntimeDllTemplateData.assign(JITPDB_DLL, JITPDB_DLL + JITPDB_DLL_SIZE);
  RuntimeHckTemplateData.assign(JITPDB_HCK, JITPDB_HCK + sizeof(DllHackInfo));
  DllHackInfo RuntimeHackInfo;
  memcpy(&RuntimeHackInfo, RuntimeHckTemplateData.data(), sizeof(RuntimeHackInfo));

  const uint32_t PeOffset = ReadU32(RuntimeDllTemplateData, 0x3C);
  const uint32_t CoffOffset = PeOffset + 4;
  const uint32_t OptionalOffset = CoffOffset + 20;
  const uint16_t OptionalMagic = ReadU16(RuntimeDllTemplateData, OptionalOffset);
  const uint32_t DataDirRelOffset = OptionalMagic == 0x20B ? 112 : 96;

  const uint32_t SectionAlignment = ReadU32(RuntimeDllTemplateData, OptionalOffset + 32);
  const uint32_t FileAlignment = ReadU32(RuntimeDllTemplateData, OptionalOffset + 36);
  const uint32_t DataDirOffset = OptionalOffset + DataDirRelOffset;
  const uint32_t DataDirCount =
      ReadU32(RuntimeDllTemplateData, DataDirOffset - sizeof(uint32_t));

  const auto &TextInfo = RuntimeHackInfo.SectionInfos[DllHackInfo::TEXT];
  const uint32_t OldTextFilePos = TextInfo.FilePos;
  const uint32_t OldTextRawSize = TextInfo.Size;
  const uint32_t TextHeaderPos = TextInfo.HeaderPos;
  const uint32_t OldTextVirtualAddress = TextInfo.VirtualAddress;
  const uint32_t OldTextVirtualSize = ReadU32(RuntimeDllTemplateData, TextHeaderPos + 8);

  uint64_t RequestedText64 = RequestedCodeSize + RequestedDataSize;
  if (RequestedText64 > UINT32_MAX) {
    LLVM_JIT_PDB_LOG(Error, "requested template size too large: %llu",
                     (unsigned long long)RequestedText64);
    return false;
  }

  const uint32_t OldTextVASpan = AlignUp(OldTextVirtualSize, SectionAlignment);
  const uint32_t RequestedText =
      std::max<uint32_t>(static_cast<uint32_t>(RequestedText64), FileAlignment);
  const uint32_t NewTextVirtualSize = AlignUp(RequestedText, SectionAlignment);
  const uint32_t NewTextRawSize = AlignUp(NewTextVirtualSize, FileAlignment);
  const uint32_t NewTextVASpan = AlignUp(NewTextVirtualSize, SectionAlignment);

  const int32_t DeltaRaw = static_cast<int32_t>(NewTextRawSize) -
                           static_cast<int32_t>(OldTextRawSize);
  const int32_t DeltaVA = static_cast<int32_t>(NewTextVASpan) -
                          static_cast<int32_t>(OldTextVASpan);
  const size_t TextRawEnd = static_cast<size_t>(OldTextFilePos + OldTextRawSize);

  if (DeltaRaw > 0) {
    RuntimeDllTemplateData.insert(RuntimeDllTemplateData.begin() + TextRawEnd,
                                  DeltaRaw, 0);
  } else if (DeltaRaw < 0) {
    RuntimeDllTemplateData.erase(RuntimeDllTemplateData.begin() + TextRawEnd +
                                     DeltaRaw,
                                 RuntimeDllTemplateData.begin() + TextRawEnd);
  }

  // TEXT section fields.
  WriteU32(RuntimeDllTemplateData, TextHeaderPos + 8, NewTextVirtualSize);
  WriteU32(RuntimeDllTemplateData, TextHeaderPos + 16, NewTextRawSize);
  RuntimeHackInfo.SectionInfos[DllHackInfo::TEXT].Size = NewTextRawSize;

  // Shift the following sections.
  for (int I = DllHackInfo::RDATA; I < DllHackInfo::SECTION_COUNT; ++I) {
    auto &Info = RuntimeHackInfo.SectionInfos[I];
    Info.VirtualAddress = std::max(0, Info.VirtualAddress + DeltaVA);
    Info.FilePos = std::max(0, Info.FilePos + DeltaRaw);
    WriteU32(RuntimeDllTemplateData, Info.HeaderPos + 12, Info.VirtualAddress);
    WriteU32(RuntimeDllTemplateData, Info.HeaderPos + 20, Info.FilePos);
  }

  // Keep .text section executable/readable/writable.
  uint32_t TextCharacteristics = ReadU32(RuntimeDllTemplateData, TextHeaderPos + 36);
  TextCharacteristics |= 0x80000000u; // IMAGE_SCN_MEM_WRITE
  TextCharacteristics |= 0x40000000u; // IMAGE_SCN_MEM_READ
  TextCharacteristics |= 0x20000000u; // IMAGE_SCN_MEM_EXECUTE
  WriteU32(RuntimeDllTemplateData, TextHeaderPos + 36, TextCharacteristics);

  // OptionalHeader updates.
  WriteU32(RuntimeDllTemplateData, OptionalOffset + 4, NewTextRawSize);
  uint32_t SizeOfInitializedData = 0;
  for (int I = DllHackInfo::RDATA; I < DllHackInfo::SECTION_COUNT; ++I)
    SizeOfInitializedData += RuntimeHackInfo.SectionInfos[I].Size;
  WriteU32(RuntimeDllTemplateData, OptionalOffset + 8, SizeOfInitializedData);

  uint32_t LastEnd = 0;
  for (int I = 0; I < DllHackInfo::SECTION_COUNT; ++I) {
    const auto &Info = RuntimeHackInfo.SectionInfos[I];
    const uint32_t VirtualSize = ReadU32(RuntimeDllTemplateData, Info.HeaderPos + 8);
    LastEnd = std::max(LastEnd, AlignUp(Info.VirtualAddress + VirtualSize, SectionAlignment));
  }
  WriteU32(RuntimeDllTemplateData, OptionalOffset + 56, LastEnd);

  // Shift any data directory RVA that points after the old .text span.
  for (uint32_t I = 0; I < DataDirCount; ++I) {
    const uint32_t EntryOffset = DataDirOffset + I * 8;
    uint32_t Rva = ReadU32(RuntimeDllTemplateData, EntryOffset);
    if (!Rva)
      continue;
    if (Rva >= OldTextVirtualAddress + OldTextVASpan) {
      Rva = static_cast<uint32_t>(std::max(0, static_cast<int32_t>(Rva) + DeltaVA));
      WriteU32(RuntimeDllTemplateData, EntryOffset, Rva);
    }
  }

  // Update absolute file positions in HCK if located after .text raw end.
  if (RuntimeHackInfo.PdbGuidPos > static_cast<int>(TextRawEnd))
    RuntimeHackInfo.PdbGuidPos = std::max(0, RuntimeHackInfo.PdbGuidPos + DeltaRaw);
  if (RuntimeHackInfo.PdbFileNamePos > static_cast<int>(TextRawEnd))
    RuntimeHackInfo.PdbFileNamePos =
        std::max(0, RuntimeHackInfo.PdbFileNamePos + DeltaRaw);

  memcpy(RuntimeHckTemplateData.data(), &RuntimeHackInfo, sizeof(RuntimeHackInfo));
  memcpy(&DllHackInfoData, RuntimeHckTemplateData.data(), sizeof(DllHackInfoData));
  return true;
}

#define LLVM_JIT_PDB_STRING_AS_PRINTF_ARG(str) int(str.size()), str.data()

void JITPDBMemoryManager::reloadDll() {
  size_t codeUsed = CodeSection.cur - CodeSection.mem.addr;
  size_t dataRWUsed = DataRWSection.cur - DataRWSection.mem.addr;
  size_t dataRUsed = DataRSection.cur - DataRSection.mem.addr;
  
  LLVM_JIT_PDB_LOG(Information,
                   "\n\t%.*s Jit Status\n"
                   "\t\t-Code memory: %zu bytes used / %zu total (%.2f%%)\n"
                   "\t\t-DataRW memory: %zu bytes used / %zu total (%.2f%%)\n"
                   "\t\t-DataRO memory: %zu bytes used / %zu total (%.2f%%)\n",
                   LLVM_JIT_PDB_STRING_AS_PRINTF_ARG(DllPath),
                   codeUsed, CodeSection.mem.size,
                   100.0 * codeUsed / CodeSection.mem.size,
                   dataRWUsed, DataRWSection.mem.size,
                   100.0 * dataRWUsed / DataRWSection.mem.size,
                   dataRUsed, DataRSection.mem.size,
                   100.0 * dataRUsed / DataRSection.mem.size);

  uint8_t *backupMem = (uint8_t *)::malloc(MemorySize);

  ptrdiff_t codeOff = (char *)CodeSection.mem.addr - (char *)MemoryStart;
  ptrdiff_t dataROff = (char *)DataRSection.mem.addr - (char *)MemoryStart;
  ptrdiff_t dataRWOff = (char *)DataRWSection.mem.addr - (char *)MemoryStart;

  ptrdiff_t codeOffInFile =
      codeOff + DllHackInfoData.SectionInfos[DllHackInfo::TEXT].FilePos;
  ptrdiff_t dataROffInFile =
      dataROff + DllHackInfoData.SectionInfos[DllHackInfo::TEXT].FilePos;
  ptrdiff_t dataRWOffInFile =
      dataRWOff + DllHackInfoData.SectionInfos[DllHackInfo::TEXT].FilePos;

  if (CodeSection.mem.addr)
    memcpy(backupMem + codeOff, CodeSection.mem.addr, CodeSection.mem.size);
  if (DataRSection.mem.addr)
    memcpy(backupMem + dataROff, DataRSection.mem.addr, DataRSection.mem.size);
  if (DataRWSection.mem.addr)
    memcpy(backupMem + dataRWOff, DataRWSection.mem.addr,
           DataRWSection.mem.size);

  unloadDll();

#define MEMORY_CONSISTENCY_TEST 0
#if MEMORY_CONSISTENCY_TEST
  if (rand() < (RAND_MAX / 2)) {
    VirtualAlloc(
        MemoryStart -
            DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress,
        DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  }
#endif

  // hack dll content
#pragma warning(disable : 4996)
  FILE *dllFD = fopen(DllPath.c_str(), "rb+");
#pragma warning(default : 4996)
  assert(dllFD);

  // rewrite time stamp
  time_t currTime;
  time(&currTime);
  fseek(dllFD, DllHackInfoData.TimeStampPos, 0);
  fwrite(&currTime, 4, 1, dllFD);

  // set TEXT section as read/write/execute
  // since DataRW section is contained in TEXT section
  // 0xE0 = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE
  uint8_t writeHack = 0xE0;
  fseek(dllFD, DllHackInfoData.SectionInfos[DllHackInfo::TEXT].HeaderPos + 39,
        0);
  fwrite(&writeHack, 1, 1, dllFD);

  ULONG_PTR imageBase =
      (ULONG_PTR)backupMem -
      DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress;
  UNWIND_INFO *unwindInfos =
      (UNWIND_INFO *)((uint8_t *)imageBase + UWDataOffset);
  RUNTIME_FUNCTION *functions =
      (RUNTIME_FUNCTION *)((uint8_t *)imageBase + RFDataOffset);

  size_t supposedCount = RFDataSize / sizeof(RUNTIME_FUNCTION);
  size_t realCount = 0;

  // try to figure out how many RUNTIME_FUNCTION really are inside the pdata
  // section (we check function bounds for weird values)
  for (auto i = 0; i < supposedCount; ++i) {
    int funcSize =
        int(functions[i].EndAddress) - int(functions[i].BeginAddress);
    if (funcSize < 0 || funcSize >= 65536) {
      supposedCount = i;
      break;
    }
  }

  // copy old unwind infos from .dll .pdata section (this allows us to see where
  // unwind infos start)
  fseek(dllFD, DllHackInfoData.SectionInfos[DllHackInfo::PDATA].FilePos, 0);
  RUNTIME_FUNCTION oldTableFirstFunc;
  fread(&oldTableFirstFunc, sizeof(RUNTIME_FUNCTION), 1, dllFD);

  DWORD offsetOtUnwindInfosInRData =
      oldTableFirstFunc.UnwindData -
      DllHackInfoData.SectionInfos[DllHackInfo::RDATA].VirtualAddress;

  // go to unwind data pos in file and write the new unwind data here
  // first zero memory
  fseek(dllFD,
        DllHackInfoData.SectionInfos[DllHackInfo::RDATA].FilePos +
            offsetOtUnwindInfosInRData,
        0);
  fwrite(unwindInfos, UWDataSize, 1, dllFD);

  RUNTIME_FUNCTION *functionsp = functions;
  for (realCount = 0; realCount < supposedCount; ++realCount) {
    RUNTIME_FUNCTION &func = *functionsp++;
    if (func.BeginAddress == 0xCCCCCCCC) // out of bound
      break;
    func.BeginAddress +=
        DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress;
    func.EndAddress +=
        DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress;
    func.UnwindInfoAddress +=
        DWORD(DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress -
              UWDataOffset + oldTableFirstFunc.UnwindData);
  }

  size_t maxCount = (DllHackInfoData.SectionInfos[DllHackInfo::PDATA].Size /
                     sizeof(RUNTIME_FUNCTION));
  if (realCount > maxCount) {
    LLVM_JIT_PDB_LOG(
        Warning, ".pdata section is not big enough to store every unwind data");
  }
#undef min
  realCount = std::min(maxCount, realCount);

  fseek(dllFD, DllHackInfoData.SectionInfos[DllHackInfo::PDATA].FilePos, 0);
  fwrite(functions, sizeof(RUNTIME_FUNCTION) * realCount, 1, dllFD);

  // insert code
  if (CodeSection.mem.addr) {
    fseek(dllFD, long(codeOffInFile), 0);
    fwrite(backupMem + codeOff, CodeSection.mem.size, 1, dllFD);
  }
  if (DataRSection.mem.addr) {
    fseek(dllFD, long(dataROffInFile), 0);
    fwrite(backupMem + dataROff, DataRSection.mem.size, 1, dllFD);
  }
  if (DataRWSection.mem.addr) {
    fseek(dllFD, long(dataRWOffInFile), 0);
    fwrite(backupMem + dataRWOff, DataRWSection.mem.size, 1, dllFD);
  }

  ::free(backupMem);

  // rewrite GUID (look for RSDS in .dll, guid is just after)
  fseek(dllFD, DllHackInfoData.PdbGuidPos, 0);
  fwrite(Guid.Guid, 1, 16, dllFD);

  // rewrite PDB/DLL matching guid
  std::string guidStr(guidToStr(Guid));

  // rewrite PDB path

  std::string WinPdbPath = PdbPath;
  for (auto &c : WinPdbPath)
    if (c == '/')
      c = '\\';
  fseek(dllFD, DllHackInfoData.PdbFileNamePos, 0);
  fwrite(WinPdbPath.data(), WinPdbPath.size() + 1, 1, dllFD);

  fclose(dllFD);

  loadDll();

  imageBase = (ULONG_PTR)DllBaseAddress;
  auto rtlCheck = RtlLookupFunctionEntry(
      uint64_t(reinterpret_cast<uint8_t *>(DllBaseAddress) +
               DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress),
      &imageBase, NULL);
  if (!rtlCheck) {
    LLVM_JIT_PDB_LOG(
        Error, "Rtl Lookup failed, unwind infos was not exported correctly");
  }
}

void JITPDBMemoryManager::loadDll() {
  DllBaseAddress = LoadLibraryA(DllPath.c_str());
  assert(DllBaseAddress);
}

void JITPDBMemoryManager::unloadDll() {
  BOOL res = FreeLibrary((HMODULE)DllBaseAddress);
  (void)res;
  assert(res);
}

uint8_t *JITPDBMemoryManager::allocateCodeSection(uintptr_t Size,
                                                  unsigned Alignment,
                                                  unsigned SectionID,
                                                  StringRef SectionName) {
  return CodeSection.allocate(this, Size, Alignment);
}

uint8_t *JITPDBMemoryManager::allocateDataSection(uintptr_t Size,
                                                  unsigned Alignment,
                                                  unsigned SectionID,
                                                  StringRef SectionName,
                                                  bool IsReadOnly) {
  uint8_t *mem;
  if (IsReadOnly)
    mem = DataRSection.allocate(this, Size, Alignment);
  else
    mem = DataRWSection.allocate(this, Size, Alignment);

  if (SectionName == ".pdata") {
    RFDataOffset = mem - (uint8_t *)DllBaseAddress;
    RFDataSize = Size;
  } else if (SectionName == ".xdata") {
    UWDataOffset = mem - (uint8_t *)DllBaseAddress;
    UWDataSize = Size;
  }
  return mem;
}

void JITPDBMemoryManager::notifyObjectLoaded(ExecutionEngine *EE,
                                             const object::ObjectFile &Obj) {
  if (StatusValue == Status::Allocating) {
    StatusValue = Status::ObjectFileEmitted;
    if (Obj.isCOFF()) {
      if (!PDBDontEmit) {
        bool result = PDBBuilder.commit(
            getPdbPath(), Guid,
            static_cast<object::COFFObjectFile const &>(Obj), PdbTplPath);
        if (!result) {
          StatusValue = Status::FailedToWritePDB;
          LLVM_JIT_PDB_LOG(Error, "Failed to write PDB on disk");
        }
      }
    } else {
      StatusValue = Status::COFFObjectFileRequired;
      LLVM_JIT_PDB_LOG(
          Error,
          "Emitted object file is not a pure COFF/CodeView file, no PDB can be "
          "emitted.");
    }
  }
}

void JITPDBMemoryManager::notifyObjectLoaded(RuntimeDyld& RTDyld,
    const object::ObjectFile& Obj) {
  JITPDBMemoryManager::notifyObjectLoaded(nullptr, Obj);
}

bool JITPDBMemoryManager::finalizeMemory(std::string *ErrMsg) {
  if (StatusValue == Status::OK) // already finalized once
    return false;
  assert((StatusValue == Status::ObjectFileEmitted ||
          StatusValue == Status::OutOfMemory ||
          StatusValue == Status::COFFObjectFileRequired) &&
         "cannot finalize while object file not emitted/loaded yet");
  if (StatusValue == Status::OutOfMemory ||
      StatusValue == Status::MemoryNotReady)
    return true;
  reloadDll();
  if (MemoryStart !=
      (reinterpret_cast<uint8_t *>(DllBaseAddress) +
       DllHackInfoData.SectionInfos[DllHackInfo::TEXT].VirtualAddress)) {
    LLVM_JIT_PDB_LOG(
        Error, "memory not available : unable to reload backing dll in same "
               "virtual space, retry required");
    StatusValue = Status::MemoryNotReady;
    return true;
  } else {
    if (NotifyModuleEmitted)
      NotifyModuleEmitted(DllBaseAddress);
    StatusValue = Status::OK;
    return false;
  }
}

namespace {
inline uint8_t *AlignUp(uint8_t *value, size_t alignment) {
  size_t mask = alignment - 1;
  return reinterpret_cast<uint8_t *>((size_t(value) + mask) & ~mask);
}
} // namespace

uint8_t *JITPDBMemoryManager::Section::allocate(JITPDBMemoryManager *mgr,
                                                size_t size, size_t align) {
  assert(mgr->StatusValue == Status::Allocating);
  assert(cur != nullptr);
  cur = AlignUp(cur, align);
  if ((cur + size) < (mem.addr + mem.size)) {
    uint8_t *ptr = cur;
    cur = ptr + size;
    return ptr;
  } else {
    mgr->StatusValue = Status::OutOfMemory;
    return nullptr;
  }
}

} // namespace llvm
