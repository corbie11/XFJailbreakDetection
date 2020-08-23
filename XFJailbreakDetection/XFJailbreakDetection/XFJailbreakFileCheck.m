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
#include <sys/syscall.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>

@implementation XFJailbreakFileCheck

+(BOOL)isJailbreakFileExist {
	BOOL check = NO;
	NSArray *jbPatternFile = [[[XFJailbreakPattern alloc] init] jailbreakFiles];
	NSFileManager *fileManager = [NSFileManager defaultManager];
	for (NSString *jbFile in jbPatternFile) {
		const char *jbFile2 = [jbFile cStringUsingEncoding:NSUTF8StringEncoding];

		//NSFileManager fileExistsAtPath
		if ([fileManager fileExistsAtPath:jbFile]) {
			NSLog(@"NSFilemanager: %@", jbFile);
			check = YES;
		}

		//System Library - opendir: Sustitute doesn't like hooking opendir :)
		DIR *dirPoint = opendir(jbFile2);
		if (dirPoint != NULL) {
			NSLog(@"opendir: %@ - %p", jbFile, dirPoint);
			check = YES;
		}

		//syscall - SYS_access
		if(syscall(SYS_access, jbFile2, F_OK) == 0) {
			NSLog(@"Syscall SYS_access: %@", jbFile);
			check = YES;
		}

		//SVC #0x80 - SYS_syscall - SYS_access, SYS_access, SYS_lstat64, SYS_stat64, SYS_statfs64, SYS_open
	#if defined __arm64__ || defined __arm64e__
		int64_t flag = ENOENT;
		__asm __volatile("mov x0, #0x21"); //access
		__asm __volatile("mov x1, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov x2, #0"); //mode
		__asm __volatile("mov x16, #0");   //syscall
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, x0" : "=r" (flag));
	#else
		int flag = ENOENT;
		__asm __volatile("mov r0, #0x21"); //access
		__asm __volatile("mov r1, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov r2, #0"); //mode
		__asm __volatile("mov r12, #0"); //syscall
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, r0" : "=r" (flag));
	#endif
		if (flag != ENOENT ) {
			NSLog(@"SVC #0x80 SYS_syscall - SYS_access: %s", jbFile2);
			check = YES;
		}

	#if defined __arm64__ || defined __arm64e__
		flag = ENOENT;
		__asm __volatile("mov x0, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov x1, #0"); //mode
		__asm __volatile("mov x16, #0x21");   //access
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, x0" : "=r" (flag));
	#else
		flag = ENOENT;
		__asm __volatile("mov r0, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov r1, #0"); //mode
		__asm __volatile("mov r12, #0x21"); //access
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, r0" : "=r" (flag));
	#endif
		if (flag != ENOENT ) {
			NSLog(@"SVC #0x80 SYS_access: %s", jbFile2);
			check = YES;
		}

		struct stat statPoint;

	#if defined __arm64__ || defined __arm64e__
		flag = ENOENT;
		__asm __volatile("mov x0, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov x1, %0" :: "r" (&statPoint)); //struct stat
		__asm __volatile("mov x16, #0x154");   //lstat64
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, x0" : "=r" (flag));
	#else
		flag = ENOENT;
		__asm __volatile("mov r0, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov x1, %0" :: "r" (&statPoint)); //struct stat
		__asm __volatile("mov r12, #0x154"); //lstat64
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, r0" : "=r" (flag));
	#endif
		if (flag != ENOENT ) {
			NSLog(@"SVC #0x80 SYS_lstat64: %s", jbFile2);
			check = YES;
		}

	#if defined __arm64__ || defined __arm64e__
		flag = ENOENT;
		__asm __volatile("mov x0, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov x1, %0" :: "r" (&statPoint)); //struct stat
		__asm __volatile("mov x16, #0x152");   //stat64
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, x0" : "=r" (flag));
	#else
		flag = ENOENT;
		__asm __volatile("mov r0, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov x1, %0" :: "r" (&statPoint)); //struct stat
		__asm __volatile("mov r12, #0x152"); //stat64
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, r0" : "=r" (flag));
	#endif
		if (flag != ENOENT ) {
			NSLog(@"SVC #0x80 SYS_stat64: %s", jbFile2);
			check = YES;
		}

		struct statfs statfsPoint;
	#if defined __arm64__ || defined __arm64e__
		flag = ENOENT;
		__asm __volatile("mov x0, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov x1, %0" :: "r" (&statfsPoint)); //struct statfs
		__asm __volatile("mov x16, #0x159");   //statfs64
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, x0" : "=r" (flag));
	#else
		flag = ENOENT;
		__asm __volatile("mov r0, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov x1, %0" :: "r" (&statfsPoint)); //struct statfs
		__asm __volatile("mov r12, #0x159"); //statfs64
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("mov %0, r0" : "=r" (flag));
	#endif
		if (flag != ENOENT ) {
			NSLog(@"SVC #0x80 SYS_statfs64: %s", jbFile2);
			check = YES;
		}

	#if defined __arm64__ || defined __arm64e__
		flag = 0;
		__asm __volatile("mov x0, %0" :: "r" (jbFile2)); //path
		__asm __volatile("mov x1, #0");
		__asm __volatile("mov x2, #0");
		__asm __volatile("mov x16, #0x5");     //open
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("bcc #0xC");
		__asm __volatile("mov x0, #0x0");
		__asm __volatile("b #0x8");
		__asm __volatile("mov x0, #0x1");
		__asm __volatile("mov %0, x0" : "=r" (flag));
	#else
		flag = 0;
		__asm __volatile("mov r0, %0" :: "r" (jbFile2)); // path
		__asm __volatile("mov r1, #0");
		__asm __volatile("mov r2, #0");
		__asm __volatile("mov r12, #0x5"); // open
		__asm __volatile("svc #0x80"); //supervisor call
		__asm __volatile("bcc #0x6");
		__asm __volatile("mov r0, 0x0");
		__asm __volatile("b #0x4");
		__asm __volatile("mov r0, #0x1");
		__asm __volatile("mov %0, r0" : "=r" (flag));
	#endif
		if(flag == 1) {
			NSLog(@"SVC #0x80 SYS_open: %s", jbFile2);
			check = YES;
		}
	}
	return check;
}

@end
