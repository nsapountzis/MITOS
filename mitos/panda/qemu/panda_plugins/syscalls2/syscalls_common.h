#ifndef __SYSCALLS_COMMON_HPP
#define __SYSCALLS_COMMON_HPP

//#include "syscalls2.h"
extern "C" {
// get definitions of QEMU types
#include "cpu.h"

}

target_long get_return_val(CPUState *env);
target_ulong mask_retaddr_to_pc(target_ulong retaddr);
target_ulong calc_retaddr(CPUState* env, target_ulong pc) ;

uint32_t get_32 (CPUState *env, uint32_t argnum);
int32_t get_s32(CPUState *env, uint32_t argnum);
uint64_t get_64(CPUState *env, uint32_t argnum);
int64_t get_s64(CPUState *env, uint32_t argnum);
target_ulong get_pointer(CPUState *env, uint32_t argnum);
uint32_t get_return_32 (CPUState *env, uint32_t argnum);
int32_t get_return_s32(CPUState *env, uint32_t argnum);
uint64_t get_return_64(CPUState *env, uint32_t argnum);
int64_t get_return_s64(CPUState *env, uint32_t argnum);
target_ulong get_return_pointer(CPUState *env, uint32_t argnum);

/* <MN FAROS: begin> */
uint32_t get_pointer_buffer_32(CPUState *env, uint32_t argnum, void **buffer, uint32_t len, uint32_t *pointer_addr);
char * get_struct_obj_attr_32(CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long *struct_size, uint32_t *ustr_addr, unsigned short *ustr_size);
char * get_struct_unicode_str_32(CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long *struct_size, uint32_t *ustr_addr, unsigned short *ustr_size);
char * get_wstr_32(CPUState* env, uint32_t arg_no, uint32_t *pointer_value, uint32_t *pointer_addr, uint32_t ustr_size);
char * get_struct_afd_info_32(CPUState* env, int nr, void **struct_content, uint32_t *struct_addr, unsigned long struct_size, uint32_t *buffer_addr, uint32_t *buffer_size, uint32_t io_control_code);

#define SYSCALL_ARG_MAX 18

/* arg1: argument value. 
 *  size1: size of arg1 in bytes
 *  arg2: argument value. (if this argument is a pointer arg2 will set)
 *  size2: size of arg2 in bytes
 *  address: if this argument is not apointer this variable will be the address of this argument
 *  if this argument is a pointer:
 *  pointer_value1: pointer's value
 *  pointer_size1: size of pointer's value
 *  pointer_value2: pointer's content (content of where this pointer refer to)
 *  pointer_size2: size of pointer's content
 *  pointer_flag: if this argument is a pointer this flag will set
 *  string_flag: if arg2 is a string this flag will set.
 */
struct syscall_arg {
    void 		    *arg1; 
    uint32_t 	    size1;
    void 		    *arg2;
    uint32_t 	    size2;
	target_ulong 	address;
	uint32_t 	    pointer_value1;
	uint32_t 	    pointer_size1;
	uint32_t 	    pointer_value2;
	uint32_t 	    pointer_size2;
	bool		    pointer_flag;
	bool		    string_flag;
};

struct syscall_args {
    struct syscall_arg args[SYSCALL_ARG_MAX];
    uint32_t arg_number;
    target_ulong retval;
};

struct ReturnPoint {
    target_ulong ordinal;
    target_ulong retaddr;
    target_ulong proc_id;
    struct syscall_args SyscallArgs;

};
/* <MN FAROS: end> */
typedef void (*pre_exec_callback_t)(CPUState*, target_ulong);

#endif
