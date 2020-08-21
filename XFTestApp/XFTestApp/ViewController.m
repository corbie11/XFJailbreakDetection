//
//  ViewController.m
//  XFTestApp
//
//  Created by xsf1re on 22/08/2020.
//  Copyright © 2020 xsf1re. All rights reserved.
//

#import "ViewController.h"
#import <XFJailbreakDetection/XFJailbreakDetection.h>

@interface ViewController ()
@end

@implementation ViewController
@synthesize JBResult;

- (void)viewDidLoad {
    [super viewDidLoad];
    
    if([XFJailbreakDetection isJailbroken])
        JBResult.text = @"Jailbroken";
    else
        JBResult.text = @"Not Jailbroken";
}
@end
