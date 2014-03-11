//
//  ViewController.m
//  Sandbox sample
//
//  Created by Boris Herman (boris42@mac.com) in 2014
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (IBAction)fetchClicked {
    NSURL *myUrl = [NSURL URLWithString: self.urlField.text];
    [self.urlField resignFirstResponder];
    [self.myWebView loadRequest:[NSURLRequest requestWithURL: myUrl]];
}

@end
