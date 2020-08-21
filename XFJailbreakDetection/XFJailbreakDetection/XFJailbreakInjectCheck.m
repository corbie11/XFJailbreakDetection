//
//  XFJailbreakInjectCheck.m
//  XFJailbreakDetection
//
//  Created by xsf1re on 22/08/2020.
//  Copyright © 2020 xsf1re. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "XFJailbreakInjectCheck.h"
#import "XFJailbreakPattern.h"
#include <dlfcn.h>

@implementation XFJailbreakInjectCheck

+(BOOL)isJailbreakInjectExist {
	NSArray *jbPatternSymbol = [[[XFJailbreakPattern alloc] init] jailbreakSymbols];
	for (NSString *jbSymbol in jbPatternSymbol) {
		const char *jbSymbol2 = [jbSymbol cStringUsingEncoding:NSUTF8StringEncoding];
		void* dlpoint = dlsym((void *)RTLD_DEFAULT, jbSymbol2);
		if(dlpoint != NULL) {
            NSLog(@"dlsym: %s - %p", jbSymbol2, dlpoint);
			return YES;
		}
	}
	return NO;
}

@end
