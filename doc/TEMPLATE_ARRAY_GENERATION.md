# JITPDB 运行时模板生成（不依赖静态预生成文件）

这份说明对应仓库里新的运行时实现：**在 `JITPDBMemoryManager` 构造阶段，直接从内置 `JITPDB_DLL/JITPDB_HCK` 生成更大容量模板**，而不是依赖静态离线工具预先生成多份模板。

## 新增 API

保留原有构造函数（兼容现有调用）：

```cpp
JITPDBMemoryManager(StringRef PdbOutputPath,
                    StringRef DllTemplatePath = StringRef(),
                    std::function<void(void*)> NotifyModuleEmittedCB = {});
```

新增可指定容量的重载：

```cpp
JITPDBMemoryManager(StringRef PdbOutputPath,
                    StringRef DllTemplatePath,
                    std::function<void(void*)> NotifyModuleEmittedCB,
                    size_t RequestedCodeSize,
                    size_t RequestedDataSize);
```

- `RequestedCodeSize`：希望预留的 JIT code 字节数。
- `RequestedDataSize`：希望预留的 JIT data（RO+RW）字节数。

## 运行时算法（内置模板路径）

当 `DllTemplatePath` 为空（使用 embedded 模板）时：

1. 复制 `JITPDB_DLL` 与 `JITPDB_HCK` 到可写缓冲区。
2. 解析 PE 头（`e_lfanew`、OptionalHeader、`SectionAlignment`、`FileAlignment`、DataDirectory）。
3. 以 `RequestedCodeSize + RequestedDataSize` 计算目标 `.text` 容量（若调用方未指定，则根据 embedded PE 的 `FileAlignment/SectionAlignment` 与运行时内存切分约束自动推导，且不低于 8KB），并按对齐规则得到新 `VirtualSize/RawSize`。
4. 对 `.text` Raw 数据做扩/缩（在 `.text` 末尾插入或删除字节）。
5. 平移 `.rdata/.pdata/.xdata` 的 `VirtualAddress` 与 `PointerToRawData`。
6. 更新 OptionalHeader 关键字段：
   - `SizeOfCode`
   - `SizeOfInitializedData`
   - `SizeOfImage`
7. 平移所有位于旧 `.text` VA 范围之后的 DataDirectory RVA（支持扩容和缩容）。
8. 同步修正 HCK 中的节信息与关键偏移（包括可能受 Raw 插入影响的 `PdbGuidPos` / `PdbFileNamePos`）。
9. `createDll()` 写盘时优先使用运行时生成后的 DLL 缓冲区。

## 结果

- 不再需要维护多份静态 `EMBEDDED_DLL.cpp/EMBEDDED_PDB.cpp`。
- 同一份内置模板在运行时可按需缩放（默认先收敛到最小模板，再按请求扩容）。
- 目前 `EMBEDDED_DLL.cpp / EMBEDDED_PDB.cpp` 仍是引导模板来源，不能直接删除；真正“去掉文件”需要补齐“从零构造最小合法 DLL/PDB”能力后再做。
- 原有 API、原有行为保持不变（不传请求容量时走老逻辑）。

## Python 生成脚本（离线瘦身）

新增 `tools/jit_template_minimizer.py`，用于把模板离线缩小后再生成 embedded array：

- 按给定 `code_size + data_size` 缩放 DLL `.text`，并重建 `.hck`；
- 对 PDB 执行 MSF 逻辑大小裁剪：`logical_size = NumBlocks * BlockSize`，去掉尾部 slack；
- 可直接输出 `EMBEDDED_DLL.generated.cpp` / `EMBEDDED_PDB.generated.cpp`。

示例：

```bash
python3 tools/jit_template_minimizer.py \
  --dll jitmem.dll \
  --pdb jitmem.pdb \
  --out-prefix out/jitmem_8k \
  --code-size $((4*1024)) \
  --data-size $((4*1024)) \
  --emit-cpp
```
