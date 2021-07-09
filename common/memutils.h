#pragma once
#include "target.h"

#define PAGE_SIZE 0x1000
#define PACKED __attribute__((packed))
#if TARGET_ARCH_64
#define HOTPATCH_ADDRESS_OFFSET 2
static unsigned char hotpatch_stub[] = {
        0x48,0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // mov rax, [Abs Jump Address]
        0xFF,0xE0,                                         // jmp rax
        0xC3,                                              // ret
};
#else
#define HOTPATCH_ADDRESS_OFFSET 1
static unsigned char hotpatch_stub[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, [Abs Jump Address]
        0xFF,0xE0,                    // jmp eax
        0xC3                          // ret

//     0x68, 0x00, 0x00 ,0x00 , 0x00,
  //   0xC3
};
#endif

struct HotPatch_Info {
    void* target_function_address;
    void* replacement_function_address;
    void* trampoline_address;
    unsigned int trampoline_size;
    unsigned char* target_original_bytes;
    unsigned int target_original_bytes_size;
};


#ifdef __cplusplus
extern "C" {
#endif
unsigned char MemUtils__get_function_address(const char* lib_name, const char* func_name, void** func_address);
unsigned char MemUtils__heap_alloc_exec_page(void** page_addr);
unsigned char MemUtils__heap_clear_exec_page(void* page_addr);

unsigned char  MemUtils__patch_ret0(void* target_addr);
unsigned char  MemUtils__patch_ret1(void* target_addr);
unsigned char MemUtils__patch_memory(void* target_addr, void* data_ptr, size_t data_len, unsigned char is_write, unsigned char is_exec);
unsigned char MemUtils__hotpatch_function(void* target_function_address, void* replacement_function_address, size_t target_original_bytes_size, struct HotPatch_Info* ctx, void** ptrampoline_address);
unsigned char MemUtils__unhotpatch_function(struct HotPatch_Info* ctx);
int HotPatch_patch(const char* module_name, const char* func_name, size_t target_original_bytes_size, void* replacement_function, void** original_function);
#ifdef __cplusplus
}
#endif

