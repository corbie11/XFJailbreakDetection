//
//  XFJailbreakFileCheck.m
//  XFJailbreakDetection
//
//  Created by xsf1re on 22/08/2020.
//  Copyright © 2020 xsf1re. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "XFJailbreakFileCheck.h"
#import "XFJailbreakPattern.h"

@implementation XFJailbreakFileCheck

+(BOOL)isJailbreakFileExist {
    NSArray *jbPatternFile = [[[XFJailbreakPattern alloc] init] jailbreakFiles];
    NSFileManager *fileManager = [NSFileManager defaultManager];
    for (NSString *jbFile in jbPatternFile) {
        if ([fileManager fileExistsAtPath:jbFile]) {
            NSLog(@"NSFilemanager: %@", jbFile);
            return YES;
        }
    }
    return NO;
}

@end
