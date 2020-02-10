//
//  Injector.m
//  dlinject
//
//  Created by Tom Zaworowski on 1/20/20.
//  Copyright © 2020 Acidbits. All rights reserved.
//

#include <pthread.h>
#include <dlfcn.h>

#import "Injector.h"
#import "MachTask.h"

struct Args {
    unsigned long long entrypoint;
    unsigned long long path;
    unsigned long long flags;
};

static const unsigned char code[] = "\x55\x48\x89\xe5\x48\x83\xec\x20\x48\x89\x7d\xf8\x48\x8b\x7d\xf8\x48\x89\x7d\xe8\x48\x8b\x7d\xe8\x48\x8b\x3f\x48\x89\x7d\xf0\x48\x8b\x7d\xf0\x48\x8b\x45\xe8\x48\x8b\x40\x08\x48\x8b\x4d\xe8\x48\x8b\x49\x10\x89\xca\x48\x89\x7d\xe0\x48\x89\xc7\x89\xd6\x48\x8b\x45\xe0\xff\xd0\x31\xd2\x89\xd0\x48\x83\xc4\x20\x5d\xc3\x66\x90";

@interface Injector ()

@end

@implementation Injector

+ (kern_return_t)injectPort:(mach_port_t)port dylibPath:(NSString *)path
{
    [self inject:port path:path];
    return KERN_SUCCESS;
}

+ (void)inject:(mach_port_t)port path:(NSString *)path
{
    MachTask *task = [[MachTask alloc] initWithPort:port];
    
    vm_address_t pthreadAttributesAddr = [task malloc:sizeof(pthread_attr_t) flags:VM_FLAGS_ANYWHERE];
    vm_address_t policyAddr = [task malloc:sizeof(int) flags:VM_FLAGS_ANYWHERE];
    vm_address_t schedAddr = [task malloc:sizeof(struct sched_param) flags:VM_FLAGS_ANYWHERE];
    
    task.entrypointHandler = ^x86_thread_state64_t(MachTask * _Nonnull task,
                                                   x86_thread_state64_t state)
    {
        // alloc pthread object
        vm_address_t dummy = [task malloc:sizeof(struct _opaque_pthread_t) flags:VM_FLAGS_ANYWHERE];
        
        // call pthread_set_self and return to 0x42
        vm_address_t entrypoint = [task entrypointForSymbol:@"_pthread_set_self"
                                                      image:@"libsystem_pthread.dylib"];
        
        x86_thread_state64_t newState = *[task stateForEntrypoint:entrypoint
                                                           canary:0x40
                                                    previousState:&state
                                                        arguments:@(dummy), nil];
        return newState;
    };
    
    [task setHandler:^x86_thread_state64_t(MachTask * _Nonnull task, x86_thread_state64_t state) {
        vm_address_t entrypoint = [task entrypointForSymbol:@"pthread_attr_init"
                                                      image:@"libsystem_pthread.dylib"];
        [task setHandler:^x86_thread_state64_t(MachTask * _Nonnull task, x86_thread_state64_t state) {
            vm_address_t entrypoint = [task entrypointForSymbol:@"pthread_attr_getschedpolicy"
                                                          image:@"libsystem_pthread.dylib"];
            [task setHandler:^x86_thread_state64_t(MachTask * _Nonnull task, x86_thread_state64_t state) {
                vm_address_t entrypoint = [task entrypointForSymbol:@"pthread_attr_setdetachstate"
                                                              image:@"libsystem_pthread.dylib"];
                [task setHandler:^x86_thread_state64_t(MachTask * _Nonnull task, x86_thread_state64_t state) {
                    vm_address_t entrypoint = [task entrypointForSymbol:@"pthread_attr_setinheritsched"
                                                                  image:@"libsystem_pthread.dylib"];
                    [task setHandler:^x86_thread_state64_t(MachTask * _Nonnull task, x86_thread_state64_t state) {
                        vm_address_t entrypoint = [task entrypointForSymbol:@"sched_get_priority_max"
                                                                      image:@"libsystem_pthread.dylib"];
                        [task setHandler:^x86_thread_state64_t(MachTask * _Nonnull task, x86_thread_state64_t state) {
                            [task writeData:(void *)state.__rax atAddress:schedAddr length:sizeof(state.__rax)];
                            vm_address_t entrypoint = [task entrypointForSymbol:@"pthread_attr_setschedparam"
                                                                          image:@"libsystem_pthread.dylib"];
                            return *[task stateForEntrypoint:entrypoint
                                                      canary:0x52
                                               previousState:&state
                                                   arguments:@(pthreadAttributesAddr), @(schedAddr), nil];
                        } forCanary:0x50];
                        return *[task stateForEntrypoint:entrypoint
                                                  canary:0x50
                                           previousState:&state
                                               arguments:@(policyAddr), nil];
                    } forCanary:0x48];
                    return *[task stateForEntrypoint:entrypoint
                                              canary:0x48
                                       previousState:&state
                                           arguments:@(pthreadAttributesAddr), @(PTHREAD_EXPLICIT_SCHED), nil];
                } forCanary:0x46];
                return *[task stateForEntrypoint:entrypoint
                                          canary:0x46
                                   previousState:&state
                                       arguments:@(pthreadAttributesAddr), @(PTHREAD_CREATE_DETACHED), nil];
            } forCanary:0x44];
            return *[task stateForEntrypoint:entrypoint
                                      canary:0x44
                               previousState:&state
                                   arguments:@(pthreadAttributesAddr), @(policyAddr), nil];
        } forCanary:0x42];
        return *[task stateForEntrypoint:entrypoint
                                  canary:0x42
                           previousState:&state
                               arguments:@(pthreadAttributesAddr), nil];
    } forCanary:0x40];
    
    [task setHandler:^x86_thread_state64_t(MachTask * _Nonnull task,
                                           x86_thread_state64_t state)
    {
        // alloc pthread object
        vm_address_t dummy = [task malloc:sizeof(pthread_t) flags:VM_FLAGS_ANYWHERE];
        vm_address_t pathArg = [task malloc:path.length + 1 flags:VM_FLAGS_ANYWHERE];
        [task writeData:(void *)path.UTF8String atAddress:pathArg length:path.length + 1];
        
        
        vm_address_t dlopenAddress = [task entrypointForSymbol:@"dlopen"
                                                  image:nil];
        vm_address_t pthreadAddress = [task entrypointForSymbol:@"pthread_create_from_mach_thread"
                                                          image:@"libsystem_pthread.dylib"];
        vm_address_t jump = [task malloc:sizeof(code)
                                   flags:VM_FLAGS_ANYWHERE];
        unsigned char *payload = malloc(sizeof(code));
        memcpy(payload, &code, sizeof(code));
        [task writeData:payload atAddress:jump length:sizeof(code)];
        [task setProtectionFlags:VM_PROT_READ | VM_PROT_EXECUTE
                       atAddress:jump
                          length:sizeof(code)];
        
        struct Args *args = malloc(sizeof(struct Args));
        args->entrypoint = dlopenAddress;
        args->path = pathArg;
        args->flags = RTLD_LAZY | RTLD_GLOBAL;
        vm_address_t argsAddr = [task malloc:sizeof(struct Args) flags:VM_FLAGS_ANYWHERE];
        [task writeData:args atAddress:argsAddr length:sizeof(struct Args)];
        free(args);
        [task setProtectionFlags:VM_PROT_READ atAddress:argsAddr length:sizeof(struct Args)];
        
        
        // call pthread_create with pthread object, NULL options and 0xdeadbea7dad entrypoint, return to 0x44
        x86_thread_state64_t newState = *[task stateForEntrypoint:pthreadAddress
                                                           canary:0xbadbeef
                                                    previousState:&state
                                                        arguments:@(dummy), @(pthreadAttributesAddr), @(jump), @(argsAddr), nil];
        return newState;
    } forCanary:0x52];
    
    [task resume];
}

@end
