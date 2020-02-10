//
//  MachTask.m
//  dlinject
//
//  Created by Tom Zaworowski on 1/25/20.
//  Copyright © 2020 Acidbits. All rights reserved.
//

#import "MachTask.h"

#include <stdlib.h>
#include "lorgnette.h"

// From xnu-2782.1.97/bsd/uxkern/ux_exception.c
typedef struct {
    mach_msg_header_t Head;
    /* start of the kernel processed data */
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    /* end of the kernel processed data */
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    mach_exception_data_t code;
    /* some times RCV_TO_LARGE probs */
    char pad[512];
} exc_msg_t;

@interface TaskHandlerStore : NSObject {
    NSMapTable *_store;
    NSMapTable *_taskStore;
}

- (NSMapTable *)handlersForPort:(mach_port_t)port;

- (void)setTask:(MachTask *)task forPort:(mach_port_t)port;
- (MachTask *)taskForPort:(mach_port_t)port;

+ (instancetype)shared;

@end

@implementation TaskHandlerStore

+ (instancetype)shared
{
    static TaskHandlerStore *handler;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        handler = [[TaskHandlerStore alloc] init];
    });
    return handler;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _store = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsCopyIn
                                       valueOptions:NSPointerFunctionsStrongMemory];
        _taskStore = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsWeakMemory
                                           valueOptions:NSPointerFunctionsWeakMemory];
    }
    return self;
}

- (NSMapTable *)handlersForPort:(mach_port_t)port
{
    NSMapTable *handlers = [_store objectForKey:@(port)];
    if (handlers == NULL) {
        handlers = [NSMapTable mapTableWithKeyOptions:NSPointerFunctionsCopyIn
                                         valueOptions:NSPointerFunctionsCopyIn];
        [_store setObject:handlers forKey:@(port)];
    }
    return handlers;
}

- (void)setTask:(MachTask *)task forPort:(mach_port_t)port
{
    [_taskStore setObject:task forKey:@(port)];
}

- (MachTask *)taskForPort:(mach_port_t)port
{
    return [_taskStore objectForKey:@(port)];
}

@end

@interface MachTask () {
    NSMutableSet *_canaries;
    NSMutableDictionary *_handlers;
    mach_port_t _exceptionPort;
    thread_t _thread;
}

@end

@implementation MachTask

NSValue* NSValueWithCanary(Canary canary)
{
    return [NSValue value:&canary
             withObjCType:@encode(Canary)];;
}

Canary CanaryFromNSValue(NSValue *value)
{
    Canary canary;
    [value getValue:&canary];
    return canary;
}

kern_return_t catch_exception(mach_port_t exception_port)
{
    assert(exception_port);

    extern boolean_t exc_server(mach_msg_header_t *request,
                                mach_msg_header_t *reply);
    kern_return_t err = mach_msg_server_once(exc_server,
                                             sizeof(exc_msg_t),
                                             exception_port, 0);
    return err;
}

- (instancetype)initWithPort:(mach_port_t)port
{
    self = [super init];
    if (self) {
        _port = port;
        _initialThreadState = calloc(1, sizeof(x86_thread_state64_t));
        _canaries = [NSMutableSet set];
        _handlers = [NSMutableDictionary dictionary];
        
        [self setupThread];
    }
    return self;
}

#define kStackSize (16 * 1024)
- (void)setupThread
{
    thread_create(_port, &_thread);
    mach_port_t exceptionPort = [self exceptionPortForThread:_thread];
    _exceptionPort = exceptionPort;
    
    vm_address_t stack = [self malloc:kStackSize flags:VM_FLAGS_ANYWHERE];
    [self setProtectionFlags:VM_PROT_READ | VM_PROT_WRITE atAddress:stack length:kStackSize];
    
    vm_address_t topOfStack = stack + kStackSize;
    if (topOfStack % 16 != 0) {
        topOfStack &= -16;
    }
    
    _initialThreadState->__rip = 0x42424242;
    _initialThreadState->__rsp = topOfStack;
    _initialThreadState->__rbp = topOfStack;
}

- (void)dealloc
{
    
}

- (BOOL)isSuspended
{
    if (&_thread == NULL) { return YES; }
    
    thread_basic_info_data_t basic_info;
    mach_msg_type_number_t info_count = THREAD_BASIC_INFO_COUNT;
    int err = thread_info((_thread),
                          THREAD_BASIC_INFO,
                          (thread_info_t)&basic_info,
                          &info_count);
    if (err != KERN_SUCCESS) return YES;

    return (basic_info.suspend_count > 0);
}

- (void)setEntrypointHandler:(TaskHandler)entrypointHandler
{
    [[[TaskHandlerStore shared] handlersForPort:_exceptionPort] setObject:entrypointHandler forKey:NSValueWithCanary(0x42424242)];
}

- (void)setHandler:(TaskHandler)handler
         forCanary:(Canary)canary
{
    NSValue *wrappedCanary = NSValueWithCanary(canary);
    [_canaries addObject:wrappedCanary];
    [_handlers setObject:handler forKey:wrappedCanary];
    
    TaskHandlerStore *store = [TaskHandlerStore shared];
    [[store handlersForPort:_exceptionPort] setObject:handler forKey:wrappedCanary];
}

- (x86_thread_state64_t *)stateForSymbol:(NSString *)symbol
                                   image:(NSString *)image
                                  canary:(Canary)canary
                           previousState:(x86_thread_state64_t *)previousState
                               arguments:(NSNumber *)args, ...
{
    vm_address_t entrypoint = [self entrypointForSymbol:symbol image:image];
    return [self stateForEntrypoint:entrypoint
                             canary:canary
                      previousState:previousState
                          arguments:args];
}

- (x86_thread_state64_t *)stateForEntrypoint:(vm_address_t )entrypoint
                                      canary:(Canary)canary
                               previousState:(x86_thread_state64_t *)previousState
                                   arguments:(NSNumber *)args,...
{
    x86_thread_state64_t *state = malloc(sizeof(x86_thread_state64_t));
    memcpy(state, previousState, sizeof(x86_thread_state64_t));
    state->__rip = entrypoint;
    state->__rbp = state->__rsp;
    state->__rsp = ({
        mach_vm_address_t stack = state->__rsp;
        vm_offset_t new_ret_value_ptr = (vm_offset_t)&(Canary){
            canary
        };
        stack -= 8;
        mach_vm_write(_port, stack, new_ret_value_ptr, sizeof(new_ret_value_ptr));
        stack;
    });
    
    if (args != nil) {
        va_list argl;
        va_start(argl, args);

        NSNumber * arg = args;
        int i = 0;
        while (arg != nil) {
            unsigned long long value = arg.unsignedLongLongValue;
            switch (i++) {
                case 0:
                    state->__rdi = value;
                    break;
                case 1:
                    state->__rsi = value;
                    break;
                case 2:
                    state->__rdx = value;
                    break;
                case 3:
                    state->__rcx = value;
                    break;
                    
                default:
                    break;
            }
            arg = va_arg(argl, NSNumber *);
        }

        va_end(argl);
    }
    
    return state;
}

- (vm_address_t)entrypointForSymbol:(NSString *)symbol
                              image:(NSString *)image
{
    if (image == nil) {
        return lorgnette_lookup(_port, symbol.UTF8String);
    }
    return lorgnette_lookup_image(_port,
                                  symbol.UTF8String,
                                  image.UTF8String);
}

- (vm_address_t)malloc:(size_t)size flags:(int)flags
{
    mach_vm_address_t memory;
    mach_vm_allocate(_port, &memory, size, flags);
    return memory;
}

- (void)free:(vm_address_t)address length:(size_t)length
{
    mach_vm_deallocate(_port, address, length);
}

- (kern_return_t)writeData:(void *)data
                 atAddress:(vm_address_t)address
                    length:(size_t)length
{
    return mach_vm_write(_port,
                         address,
                         (vm_offset_t)data,
                         (mach_msg_type_number_t)length);
}

- (kern_return_t)setProtectionFlags:(vm_prot_t)flags
                          atAddress:(vm_address_t)address
                             length:(size_t)length
{
    return mach_vm_protect(_port, address, length, 0, flags);
}

- (void)resume
{
    if (_thread) {
        thread_set_state(_thread,
                         x86_THREAD_STATE64,
                         (thread_state_t)_initialThreadState,
                         x86_THREAD_STATE64_COUNT);
        thread_resume((_thread));
        
        while(1) {
            catch_exception(_exceptionPort);
            if (!self.isSuspended) continue;
            [self end];
            break;
        }
    }
}

- (void)suspend
{
    if (_thread) {
        thread_suspend(_thread);
    }
}

- (void)end
{
    if (_thread) {
        thread_terminate(_thread);
    }
}

#pragma mark - Private

- (mach_port_t)exceptionPortForThread:(thread_t )thread
{
    // Setup an exception port for the thread
    mach_port_t exception_port = 0;
    mach_port_allocate(mach_task_self(),
                       MACH_PORT_RIGHT_RECEIVE,
                       &exception_port);
    mach_port_insert_right(mach_task_self(),
                           exception_port,
                           exception_port,
                           MACH_MSG_TYPE_MAKE_SEND);
    thread_set_exception_ports(thread,
                               EXC_MASK_BAD_ACCESS,
                               exception_port,
                               EXCEPTION_STATE_IDENTITY,
                               x86_THREAD_STATE64);
    [[TaskHandlerStore shared] setTask:self forPort:exception_port];
    return exception_port;
}

- (void)detroyExceptionPort:(mach_port_t)exceptionPort
{
    mach_port_deallocate(mach_task_self(), exceptionPort);
}

@end

static
kern_return_t catch_x86_64_exception(task_t task,
                                     mach_port_t thread,
                                     x86_thread_state64_t *in_state,
                                     x86_thread_state64_t *out_state,
                                     mach_port_t exception_port)
{
    TaskHandlerStore *store = [TaskHandlerStore shared];
    Canary canary = in_state->__rip;
    if (canary == 0xbadbeef) {
        thread_suspend(thread);
        return MIG_NO_REPLY;
    }
    NSMapTable *handlers = [store handlersForPort:exception_port];
    MachTask *machTask = [store taskForPort:exception_port];
    TaskHandler handler = [handlers objectForKey:NSValueWithCanary(canary)];
    if (handler) {
        x86_thread_state64_t newState = handler(machTask, *in_state);
        memcpy(out_state, &newState, sizeof(newState));
    } else {
//        memset(out_state, 0, sizeof(*out_state));
//        out_state->__rax = (0);
//        // Since we return MIG_NO_REPLY the kernel won't update the thread's
//        // state, so we have to do it manually
//        thread_set_state(thread, x86_THREAD_STATE64,
//                         (thread_state_t)out_state,
//                         x86_THREAD_STATE64_COUNT);
//        thread_suspend(thread);
//        return MIG_NO_REPLY;
    }
    return KERN_SUCCESS;
}

__attribute__((visibility("default")))
kern_return_t
catch_exception_raise_state_identity(mach_port_t exception_port,
                                     mach_port_t thread,
                                     mach_port_t task,
                                     exception_type_t exception,
                                     exception_data_t code,
                                     mach_msg_type_number_t code_count,
                                     int *flavor,
                                     thread_state_t in_state,
                                     mach_msg_type_number_t in_state_count,
                                     thread_state_t out_state,
                                     mach_msg_type_number_t *out_state_count)
{
#pragma unused (exception_port, exception, code, code_count)
#pragma unused (in_state_count, out_state, out_state_count)

    if (*flavor == x86_THREAD_STATE64) {
        x86_thread_state64_t *in_state64 = (x86_thread_state64_t *)in_state;
        x86_thread_state64_t *out_state64 = (x86_thread_state64_t *)out_state;

        *out_state_count = x86_THREAD_STATE64_COUNT;
        return catch_x86_64_exception(task,
                                      thread,
                                      in_state64,
                                      out_state64,
                                      exception_port);

    }

    // It's not x86_64 so we have nothing to do with it
    return KERN_FAILURE;
}
