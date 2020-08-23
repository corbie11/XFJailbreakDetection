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
#include <mach-o/dyld.h>
#include <mach/task_info.h>
#include <mach/task.h>
#include <mach-o/dyld_images.h>
#include <crt_externs.h>

typedef char int8;
typedef int8 BYTE;

@implementation XFJailbreakInjectCheck

+(BOOL)isJailbreakInjectExist {
	BOOL check = NO;

	//Symbol Check
	NSArray *jbPatternSymbol = [[[XFJailbreakPattern alloc] init] jailbreakSymbols];
	for (NSString *jbSymbol in jbPatternSymbol) {
		const char *jbSymbol2 = [jbSymbol cStringUsingEncoding:NSUTF8StringEncoding];
		void* dlpoint = dlsym((void *)RTLD_DEFAULT, jbSymbol2);
		if(dlpoint != NULL) {
			NSLog(@"dlsym: %s - %p", jbSymbol2, dlpoint);
			check = YES;
		}
	}

	//Dyld Check
	NSArray *jbPatternDyld = [[[XFJailbreakPattern alloc] init] jailbreakDylds];
	uint32_t count = _dyld_image_count();
	Dl_info dylib_info;
	for(uint32_t i = 0; i < count; i++) {
		dladdr(_dyld_get_image_header(i), &dylib_info);
		for (NSString *jbDyld in jbPatternDyld) {
			NSString *detectedDyld = [NSString stringWithUTF8String:dylib_info.dli_fname];
			if([detectedDyld containsString:jbDyld]) {
				NSLog(@"dyld: %@", detectedDyld);
				check = YES;
				break;
			}
		}
	}

	//Dyld Check2
	integer_t task_info_out[TASK_DYLD_INFO_COUNT];
	mach_msg_type_number_t task_info_outCnt = TASK_DYLD_INFO_COUNT;
	if(task_info(mach_task_self_, TASK_DYLD_INFO, task_info_out, &task_info_outCnt) == KERN_SUCCESS) {
		struct task_dyld_info dyld_info = *(struct task_dyld_info*)(void*)(task_info_out);
		struct dyld_all_image_infos* infos = (struct dyld_all_image_infos *) dyld_info.all_image_info_addr;
		struct dyld_uuid_info* pUuid_info  = (struct dyld_uuid_info*) infos->uuidArray;

		for( int i = 0; i < infos->uuidArrayCount; i++, pUuid_info += 1)
		{
			const struct mach_header_64* mheader = (const struct mach_header_64*)pUuid_info->imageLoadAddress;
			if (mheader->filetype == MH_DYLIB) {
				if(mheader->magic == MH_MAGIC_64 && mheader->ncmds > 0)
				{
					void *loadCmd = (void*)(mheader + 1);
					struct segment_command_64 *sc = (struct segment_command_64 *)loadCmd;
					for (int index = 0; index < mheader->ncmds; ++index, sc = (struct segment_command_64*)((BYTE*)sc + sc->cmdsize))
					{
						if (sc->cmd == LC_ID_DYLIB) {
							struct dylib_command *dc = (struct dylib_command *)sc;
							struct dylib dy = dc->dylib;
							const char *detectedDyld = (char*)dc + dy.name.offset;
							for (NSString *jbDyld in jbPatternDyld) {
								if([[NSString stringWithUTF8String:detectedDyld] containsString:jbDyld]) {
									NSLog(@"dyld2: %s", detectedDyld);
									check = YES;
									break;
								}
							}
						}
					}
				}
			}
		}
	}

	//Env Check
	NSArray *jbPatternEnv = [[[XFJailbreakPattern alloc] init] jailbreakEnvs];

	char ***envp = _NSGetEnviron();
	if (envp) {
		char **env = *envp;
		while (*env) {
			for (NSString *jbEnv in jbPatternEnv) {
				if([[NSString stringWithUTF8String:*env] containsString:jbEnv]) {
					NSLog(@"env: %s", *env);
					check = YES;
				}
			}
			env++;
		}
	}

	//Env Check2
	extern char **environ;
	for(int i=0; environ[i]; i++)
	{
		for (NSString *jbEnv in jbPatternEnv) {
			if([[NSString stringWithUTF8String:environ[i]] containsString:jbEnv]) {
				NSLog(@"env2 <%d>: %s", i, environ[i]);
				check = YES;
			}
		}
	}

	return check;
}

@end
