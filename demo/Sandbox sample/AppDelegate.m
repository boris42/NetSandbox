//
//  AppDelegate.m
//  Sandbox sample
//
//  Created by Boris Herman (boris42@mac.com) in 2014
//

#import "AppDelegate.h"
#import "NetSandbox.h"

@implementation AppDelegate

- (BOOL)application: (UIApplication *)application didFinishLaunchingWithOptions: (NSDictionary *)launchOptions
{
    // register our NetSandbox class containing NSURLProtocol implementation
    [NSURLProtocol registerClass:[NetSandbox class]];
    return YES;
}

@end
