//
//  XFJailbreakPattern.h
//  XFJailbreakDetection
//
//  Created by xsf1re on 22/08/2020.
//  Copyright © 2020 xsf1re. All rights reserved.
//

@interface XFJailbreakPattern: NSObject
-(NSArray *)jailbreakFiles;
-(NSArray *)jailbreakSymbols;
-(NSArray *)jailbreakDylds;
-(NSArray *)jailbreakURLs;
-(NSArray *)jailbreakEnvs;
@end
