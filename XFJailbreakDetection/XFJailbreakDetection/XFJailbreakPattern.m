//
//  XFJailbreakPattern.m
//  XFJailbreakDetection
//
//  Created by xsf1re on 22/08/2020.
//  Copyright © 2020 xsf1re. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "XFJailbreakPattern.h"

@implementation XFJailbreakPattern

-(NSArray *)jailbreakFiles {
	NSArray *file = [NSArray arrayWithObjects:
	                 @"/Applications/Cydia.app",
	                 @"/Applications/Sileo.app",
	                 @"/var/binpack",
	                 @"/Library/MobileSubstrate/DynamicLibraries",
	                 @"/Library/PreferenceBundles/LibertyPref.bundle",
	                 @"/Library/PreferenceBundles/ShadowPreferences.bundle",
	                 @"/Library/PreferenceBundles/ABypassPrefs.bundle",
	                 @"/Library/PreferenceBundles/FlyJBPrefs.bundle",
	                 @"/usr/lib/libhooker.dylib",
	                 @"/usr/lib/libsubstitute.dylib",
	                 @"/usr/lib/substrate",
	                 @"/usr/lib/TweakInject",
	                 nil];
	return file;
}

-(NSArray *)jailbreakSymbols {
	NSArray *symbol = [NSArray arrayWithObjects:
	                   @"MSHookFunction",
	                   @"MSHookMessageEx",
	                   @"MSFindSymbol",
	                   @"MSGetImageByName",
	                   @"ZzBuildHook",
	                   @"DobbyHook",
	                   @"LHHookFunctions",
	                   nil];
	return symbol;
}

-(NSArray *)jailbreakDylds {
	NSArray *dyld = [NSArray arrayWithObjects:
	                 @"MobileSubstrate",
	                 @"TweakInject",
	                 @"libhooker",
	                 @"substrate",
	                 @"SubstrateLoader",
	                 @"SubstrateInserter",
	                 @"SubstrateBootstrap",
	                 @"substrate",
	                 @"ABypass",
	                 @"FlyJB",
	                 @"substitute",
	                 @"Cephei",
	                 @"rocketbootstrap",
	                 @"Electra",
	                 nil];
	return dyld;
}

-(NSArray *)jailbreakURLs {
	NSArray *url = [NSArray arrayWithObjects:
	                @"cydia://",
	                @"sileo://",
	                @"zbra://",
	                @"filza://",
	                @"activator://",
	                nil];
	return url;
}

-(NSArray *)jailbreakEnvs {
	NSArray *env = [NSArray arrayWithObjects:
	                @"_MSSafeMode",
	                @"substitute",
	                nil];
	return env;
}

@end
