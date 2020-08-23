//
//  XFJailbreakDetection.m
//  XFJailbreakDetection
//
//  Created by xsf1re on 22/08/2020.
//  Copyright © 2020 xsf1re. All rights reserved.
//

#import "XFJailbreakDetection.h"
#import "XFJailbreakFileCheck.h"
#import "XFJailbreakInjectCheck.h"
#import "XFJailbreakURLCheck.h"

@implementation XFJailbreakDetection
+ (BOOL)isJailbroken
{
	BOOL isJB = NO;
#if !(TARGET_IPHONE_SIMULATOR)
	if([XFJailbreakFileCheck isJailbreakFileExist])
		isJB = YES;

	if([XFJailbreakInjectCheck isJailbreakInjectExist])
		isJB = YES;

	if([XFJailbreakURLCheck isJailbreakURLAvailable])
		isJB = YES;

#endif
	return isJB;
}

@end
