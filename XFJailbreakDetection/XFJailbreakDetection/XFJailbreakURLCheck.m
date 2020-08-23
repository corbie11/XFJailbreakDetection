//
//  XFJailbreakURLCheck.m
//  XFJailbreakDetection
//
//  Created by xsf1re on 22/08/2020.
//  Copyright © 2020 xsf1re. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "XFJailbreakURLCheck.h"
#import "XFJailbreakPattern.h"

@implementation XFJailbreakURLCheck

+(BOOL)isJailbreakURLAvailable {
	BOOL check = NO;

	NSArray *jbPatternURL = [[[XFJailbreakPattern alloc] init] jailbreakURLs];

	for (NSString *jbURL in jbPatternURL) {
		if([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:jbURL]]) {
			NSLog(@"URLOpenAvailable = %@", jbURL);
			check = YES;
		}
	}
	return check;
}

@end
