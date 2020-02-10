//
//  Injector.h
//  dlinject
//
//  Created by Tom Zaworowski on 1/20/20.
//  Copyright © 2020 Acidbits. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface Injector : NSObject

+ (kern_return_t)injectPort:(mach_port_t)port dylibPath:(NSString *)path;

@end

NS_ASSUME_NONNULL_END
