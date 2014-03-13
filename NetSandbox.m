//
//  NetSandbox.m
//  Sandbox sample
//
//  Created by Boris Herman (boris42@mac.com) in 2014
//

#import "NetSandbox.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

@interface NetSandbox()
// property that holds the connection data, populated on delegation and persists thru events
@property (nonatomic, strong) NSURLConnection *connection;
@end

@implementation NetSandbox

// explicit function declaration from Security framework
CFDataRef SecCertificateCopyPublicKeySHA1Digest(SecCertificateRef);

// need to implement this method for proper NSURLProtocol delegate mechanism
+ (NSURLRequest *)canonicalRequestForRequest: (NSURLRequest *)request {
    return request;
}

// need to implement this method for proper NSURLProtocol delegate mechanism
- (void)stopLoading {
    [self.connection cancel];
}

// need to implement this method for proper NSURLConnectionDelegate protocol mechanism
- (void)connection: (NSURLConnection *)connection didReceiveData: (NSData *)data {
    [self.client URLProtocol: self didLoadData: data];
}

// need to implement this method for proper NSURLConnectionDelegate protocol mechanism
- (void)connection: (NSURLConnection *)connection didReceiveResponse: (NSURLResponse *)response {
    [self.client URLProtocol: self didReceiveResponse: response cacheStoragePolicy: NSURLCacheStorageAllowedInMemoryOnly];
}

// need to implement this method for proper NSURLConnectionDelegate protocol mechanism
- (void)connectionDidFinishLoading: (NSURLConnection *)connection {
    [self.client URLProtocolDidFinishLoading: self];
    self.connection = nil;
}

// need to implement this method for proper NSURLProtocol delegate mechanism
// we return true if the scheme is either http or https
// and the request hasn't been handled yet
+ (BOOL)canInitWithRequest: (NSURLRequest *)request {
    BOOL canHandle = false;
    NSString *reqScheme = [[[request URL] scheme] lowercaseString];
    if ( [reqScheme isEqualToString: @"http"] || [reqScheme isEqualToString: @"https"] )
        canHandle = ([NSURLProtocol propertyForKey: @"NetSandbox" inRequest: request] == nil);
    return canHandle;
}

// need to implement this method for proper NSURLProtocol delegate mechanism
// main intercept entry point for NSURL requests
- (void)startLoading {
    NSMutableURLRequest *newRequest = [self.request mutableCopy];
    // we check the URL request against network entitlements manifest
    if ( ![NetSandbox checkURL: [newRequest URL]] ) {
        // check failed, we note the URL in the request and set URL to empty which fails the request
        NSString *blockedURL = [NSString stringWithFormat: @"%@://%@:%@", [[newRequest URL] scheme], [[newRequest URL] host], [[newRequest URL] port]] ;
        [NSURLProtocol setProperty: blockedURL forKey: @"BlockedURL" inRequest: newRequest];
        [newRequest setURL: [NSURL URLWithString: @""]];
    }
    // note mark the request as handled
    [NSURLProtocol setProperty: @YES forKey: @"NetSandbox" inRequest: newRequest];
    self.connection = [NSURLConnection connectionWithRequest: newRequest delegate: self];
}

// need to implement this method for proper NSURLConnectionDelegate mechanism and to report errors
- (void)connection: (NSURLConnection *)connection didFailWithError: (NSError *)error {
    [self.client URLProtocol: self didFailWithError: error];
    self.connection = nil;
    // we retrieve the url from the handled and refused request
    NSString *problemURL = [NSURLProtocol propertyForKey: @"BlockedURL" inRequest: [connection originalRequest]];
    // if SSL handshake was cancelled, retrieve hostname
    if (error.code == kCFURLErrorUserCancelledAuthentication)
        problemURL = connection.currentRequest.URL.host;
    // display error in the console
    NSLog(@"Error: %@ - %@", problemURL, [error localizedDescription]);
}

// forward DNS lookup - get all IP addresses for a single hostname
// returns a NSArray of strings with IP addresses
+ (NSArray *)addressesForHostname: (NSString *)hostname {
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

// reverse DNS lookup - get all hostnames for a single given IP address
// returns a NSArray of strings with hostnames
+ (NSArray *)hostnamesForAddress: (NSString *)address {
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

// perform full circle DNS check - for a given hostname verify that
// at least one of its IP addresses resolves back to its hostname
// returns TRUE if match is found
+ (BOOL)fullDNScheck: (NSString *)hostname {
    for ( NSString *anAddress in [NetSandbox addressesForHostname: hostname] )
        for ( NSString *aHost in [NetSandbox hostnamesForAddress: anAddress] )
            if( [hostname caseInsensitiveCompare: aHost] == NSOrderedSame )
                return true;
    return false;
}

// retrieve bundled property list file with network entitlements and
// select entries for a specific hostname
// returns a NSDictionary with entries
+ (NSDictionary *)entitlementsForHost: (NSString *)hostname {
    NSString *plistPath = [[NSBundle mainBundle] pathForResource: @"NetworkEntitlements" ofType: @"plist"];
    NSData *plistXML = [[NSFileManager defaultManager] contentsAtPath: plistPath];
    NSDictionary *allNetEntitlements = [NSPropertyListSerialization propertyListWithData: plistXML options: NSPropertyListImmutable format: nil error: nil];
    for ( NSDictionary *aDict in [allNetEntitlements objectForKey: @"NetworkEntitlements"] )
        if ( [[aDict valueForKey: @"hostname"] caseInsensitiveCompare: hostname] == NSOrderedSame )
            return aDict;
    return nil;
}

// enumerate network interfaces and determine whether
// a VPN service has an IP address assigned
// returns a Boolean TRUE or FALSE
+ (BOOL)isVpnActive {
    BOOL result = FALSE;
    struct ifaddrs *interfaces;
    if ( !getifaddrs (&interfaces) ) {
        struct ifaddrs *interface;
        for ( interface = interfaces; interface; interface = interface -> ifa_next) {
            const struct sockaddr_in *addr = (const struct sockaddr_in*) interface -> ifa_addr;
            if ( addr && ( addr -> sin_family == AF_INET || addr -> sin_family == AF_INET6 ) ) {
                NSString *name = [NSString stringWithUTF8String: interface -> ifa_name];
                if ( ([name isEqual: @"ppp0"]) || [name isEqual: @"utun0"] ) {
                    char addrBuf[INET6_ADDRSTRLEN];
                    if ( inet_ntop ( addr -> sin_family, &addr -> sin_addr, addrBuf, sizeof(addrBuf) ) )
                        result = TRUE;
                }
            }
        }
        freeifaddrs (interfaces);
    }
    return result;
}

// utility method to convert a bag of bits in NSData to hexadecimal string
// returns a NSString
+ (NSString*)dataToHex: (NSData *)myData {
    NSUInteger n = myData.length;
    NSMutableString* hexString = [NSMutableString stringWithCapacity: (n * 2)];
    const unsigned char* buf = [myData bytes];
    for ( int i = 0; i < n; i++ )
        [hexString appendFormat: @"%02x", buf[i]];
    return hexString;
}

// need to implement for NSURLConnectionDelegate to intercept exchange before establishing TLS/SSL session
- (void)connection: (NSURLConnection *)connection willSendRequestForAuthenticationChallenge: (NSURLAuthenticationChallenge *)challenge {
    NSString *host = [challenge.protectionSpace host];
    NSArray *pubKeyHashes = [[NetSandbox entitlementsForHost: host] valueForKey: @"pubkeyhashes"];
    // if manifest specifies server public key hashes we compare them
    if ( pubKeyHashes ) {
        if( [challenge.protectionSpace.authenticationMethod isEqualToString: NSURLAuthenticationMethodServerTrust] ) {
            SecTrustRef serverTrust = [challenge.protectionSpace serverTrust];
            SecTrustResultType trustResult;
            SecTrustEvaluate (serverTrust, &trustResult);
            if ( trustResult == kSecTrustResultUnspecified ) {
                // get server certificate and its public key SHA1 hash
                SecCertificateRef certificate = SecTrustGetCertificateAtIndex (serverTrust, 0);
                CFDataRef pubKeySha1Bytes = (CFDataRef) SecCertificateCopyPublicKeySHA1Digest (certificate);
                NSString *pubKeySha1Hex = [NetSandbox dataToHex: (__bridge NSData *) (pubKeySha1Bytes)];
                CFRelease (pubKeySha1Bytes);
                // iterate thru enumerated hashes from the manifest
                // continue if found, cancel handshake if not,
                // causing a kCFURLErrorUserCancelledAuthentication error
                BOOL hashFound = false;
                for ( NSString *aHash in pubKeyHashes ) {
                    if ( [pubKeySha1Hex caseInsensitiveCompare: aHash]  == NSOrderedSame ) {
                        hashFound = TRUE;
                        break;
                    }
                }
                if (hashFound) {
                    [challenge.sender useCredential: [NSURLCredential credentialForTrust: challenge.protectionSpace.serverTrust] forAuthenticationChallenge: challenge];
                }
                else
                    [[challenge sender] cancelAuthenticationChallenge: challenge];
            }
        }
    }
    else
        [challenge.sender useCredential: [NSURLCredential credentialForTrust: challenge.protectionSpace.serverTrust] forAuthenticationChallenge: challenge];
}

// method to check a NSURL against entitlements manifest
// checks conditions as mandated
// returns TRUE if it passes all checks, FALSE if not
+ (BOOL)checkURL: (NSURL *)url {
    BOOL urlAllowed = false;
    // extract parameters from the URL
    NSURL *myUrl = url.standardizedURL;
    NSString *myHost = [myUrl.host lowercaseString];
    NSString *myScheme = [myUrl.scheme lowercaseString];
    int myPort = myUrl.port.intValue;
    if ( !myPort ) {
        // default ports for scheme if not set
        if ( [myScheme isEqualToString: @"http"] ) myPort = 80;
        if ( [myScheme isEqualToString: @"https"] ) myPort = 443;
    }
    // retrieve host entitlements
    NSDictionary *hostEntitlements = [NetSandbox entitlementsForHost: myHost];
    if ( hostEntitlements ) {
        // if host listed and no other conditions, allow it
        urlAllowed = TRUE;
        // full cirle DNS mandated?
        if ( [[hostEntitlements valueForKey: @"fullDNS"] boolValue] )
            urlAllowed = [NetSandbox fullDNScheck: myHost];
        // specific scheme mandated?
        NSArray *listedSchemes = [hostEntitlements valueForKey: @"schemes"];
        if ( urlAllowed && [listedSchemes count] ) {
            urlAllowed = FALSE;
            for ( NSString *aScheme in listedSchemes )
                if ( [myScheme caseInsensitiveCompare: aScheme]  == NSOrderedSame ) {
                    urlAllowed = TRUE;
                    break;
                }
        }
        // port number specified?
        int listedPort = [[hostEntitlements valueForKey: @"port"] intValue];
        if ( urlAllowed && listedPort )
            urlAllowed = ( listedPort == myPort );
        // VPN mandated?
        if ( urlAllowed && [[hostEntitlements valueForKey: @"VPN"] boolValue] )
            urlAllowed = [NetSandbox isVpnActive];
    }
    return urlAllowed;
}

@end
