//
//  MachTask.h
//  dlinject
//
//  Created by Tom Zaworowski on 1/25/20.
//  Copyright © 2020 Acidbits. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface MachTask : NSObject

typedef x86_thread_state64_t (^TaskHandler)(MachTask *, x86_thread_state64_t);
typedef unsigned long long Canary;

@property (assign, readonly, nonatomic) mach_port_t port;
@property (assign, readonly, nonatomic) x86_thread_state64_t *initialThreadState;
@property (copy, nonatomic) TaskHandler entrypointHandler;

@property (assign, readonly, nonatomic, getter=isSuspended) BOOL suspended;

- (instancetype)initWithPort:(mach_port_t)port;

- (void)setHandler:(TaskHandler)handler
         forCanary:(Canary)canary;

- (x86_thread_state64_t *)stateForSymbol:(NSString *)symbol
                                   image:(NSString *)image
                                  canary:(Canary)canary
                           previousState:(x86_thread_state64_t *)previousState
                               arguments:(NSNumber *)args,...;

- (x86_thread_state64_t *)stateForEntrypoint:(vm_address_t)entrypoint
                                      canary:(Canary)canary
                               previousState:(x86_thread_state64_t *)previousState
                                   arguments:(NSNumber *)args,...;

- (vm_address_t)entrypointForSymbol:(NSString *)symbol
                              image:(NSString * _Nullable)image;

- (vm_address_t)malloc:(size_t)size flags:(int)flags;
- (void)free:(vm_address_t)address length:(size_t)length;
- (kern_return_t)writeData:(void *)data
                 atAddress:(vm_address_t)address
                    length:(size_t)length;
- (kern_return_t)setProtectionFlags:(int)flags
                          atAddress:(vm_address_t)address
                             length:(size_t)length;

- (void)resume;
- (void)suspend;
- (void)end;

@end


NS_ASSUME_NONNULL_END
