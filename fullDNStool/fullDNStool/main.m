//
//  main.m
//  fullDNStool
//
//  Created by Boris Herman on 13/03/14.
//  Copyright (c) 2014 Sight & Sound s.p. All rights reserved.
//
#define NSPrint(FORMAT, ...) fprintf(stdout,"%s\n", [[NSString stringWithFormat:FORMAT, ##__VA_ARGS__] UTF8String]);

#include <netdb.h>

NSArray *addressesForHostname(NSString *hostname) {
    NSMutableArray *addresses = [NSMutableArray array];
    CFHostRef hostRef = CFHostCreateWithName (kCFAllocatorDefault, (__bridge CFStringRef) hostname);
    if ( hostRef ) {
        if ( CFHostStartInfoResolution (hostRef, kCFHostAddresses, nil) ) {
            CFArrayRef addressesRef = CFHostGetAddressing (hostRef, nil);
            if ( addressesRef ) {
                char ipAddress[INET6_ADDRSTRLEN];
                CFIndex numAddresses = CFArrayGetCount (addressesRef);
                for ( CFIndex i = 0; i < numAddresses; i++) {
                    struct sockaddr *address = (struct sockaddr *) CFDataGetBytePtr (CFArrayGetValueAtIndex (addressesRef, i) );
                    if ( address ) {
                        getnameinfo (address, address -> sa_len, ipAddress, INET6_ADDRSTRLEN, nil, 0, NI_NUMERICHOST);
                        [addresses addObject: [NSString stringWithCString: ipAddress encoding: NSASCIIStringEncoding]];
                    }
                }
            }
        }
        CFRelease(hostRef);
    }
    return addresses;
}

NSArray *hostnamesForAddress(NSString *address) {
    struct addrinfo hints;
    struct addrinfo *result = nil;
    memset (&hints, 0, sizeof (hints));
    hints.ai_flags = AI_NUMERICHOST;
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = 0;
    NSArray *hostnames;
    if ( getaddrinfo( [address cStringUsingEncoding: NSASCIIStringEncoding], nil, &hints, &result) == 0 ) {
        CFDataRef addressRef = CFDataCreate (nil, (UInt8 *) result -> ai_addr, result -> ai_addrlen);
        if ( addressRef ) {
            freeaddrinfo (result);
            CFHostRef hostRef = CFHostCreateWithAddress (kCFAllocatorDefault, addressRef);
            if ( hostRef ) {
                if ( CFHostStartInfoResolution (hostRef, kCFHostNames, nil) )
                    hostnames = (__bridge NSArray *) (CFHostGetNames (hostRef, nil));
                CFRelease(hostRef);
            }
            CFRelease(addressRef);
        }
    }
    return hostnames;
}

BOOL fullDNScheck(NSString *hostname) {
    for ( NSString *anAddress in addressesForHostname(hostname) )
        for ( NSString *aHost in (hostnamesForAddress(anAddress) ))
            if( [hostname caseInsensitiveCompare: aHost] == NSOrderedSame )
                return true;
    return false;
}

int main(int argc, const char * argv[])
{
    @autoreleasepool {
        if (argc == 2) {
            NSString *hostName = [NSString stringWithUTF8String:argv[1]];
            NSArray *ipAddrs = addressesForHostname(hostName);
            if ([ipAddrs count]>0) {
                if (fullDNScheck(hostName)) {
                    NSPrint(@"%@  PASSES  full circle DNS check", hostName);
                }
                else {
                    NSPrint(@"%@ DOES NOT PASS full circle DNS check.", hostName);
                    for (NSString *anAddress in ipAddrs) {
                        NSArray *h =hostnamesForAddress(anAddress);
                        NSPrint(@"%@ - %@",anAddress, [h componentsJoinedByString:@","]);
                    }
                }
            }
            else {
                NSPrint(@"Host: %@ does not resolve", hostName);
            }
        }
        else {
            NSPrint(@"Wrong number of parameters. Usage: fullDNStool <hostname>");
            return 1;
        }
    }
    return 0;
}

