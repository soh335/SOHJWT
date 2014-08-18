//
//  SOHJWTAlgorithm.m
//  SOHJWT
//
//  Created by soh335 on 2014/08/18.
//  Copyright (c) 2014年 soh335. All rights reserved.
//

#import "SOHJWTAlgorithm.h"

#import <CommonCrypto/CommonCrypto.h>

@interface SOHJWTAlgorithm ()

@property (nonatomic) NSMutableDictionary *dict;

@end

@implementation SOHJWTAlgorithm

+ (instancetype)shared
{
    static SOHJWTAlgorithm *jwtAlgorithm;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^(void){
        jwtAlgorithm = [[SOHJWTAlgorithm alloc] init];
    });
    
    return jwtAlgorithm;
}

- (id)init
{
    if (self = [super init]) {
        _dict = [NSMutableDictionary dictionary];
        
        [self setAlgorithm:[[SOHJWTAlgorithmNone alloc] init]];
        [self setAlgorithm:[[SOHJWTAlgorithmHmacSha256 alloc] init]];
    }
    
    return self;
}

- (void)setAlgorithm:(id<SOHJWTAlgorithmProtocol>)algorithm
{
    [_dict setObject:algorithm forKey:[algorithm name]];
}

- (id<SOHJWTAlgorithmProtocol>)getAlgorithm:(NSString *)name
{
    return [_dict objectForKey:name];
}

@end

#pragma mark - none

@implementation SOHJWTAlgorithmNone

- (NSString *)name
{
    return @"none";
}

- (NSData *)sign:(NSData *)key data:(NSData *)data
{
    return [@"" dataUsingEncoding:NSUTF8StringEncoding];
}

- (BOOL)verify:(NSData *)signature key:(NSData *)key data:(NSData *)data
{
    return YES;
}

@end

#pragma mark - hmac

@implementation SOHJWTAlgorithmHmacSha256

- (NSString *)name
{
    return @"HS256";
}

- (NSData *)sign:(NSData *)key data:(NSData *)data
{
    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, key.bytes, key.length, data.bytes, data.length, &cHMAC);
    return [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
}

- (BOOL)verify:(NSData *)signature key:(NSData *)key data:(NSData *)data
{
    NSData *sign = [self sign:key data:data];
    return [sign isEqualToData:signature];
}

@end
