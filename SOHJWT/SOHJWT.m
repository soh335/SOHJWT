//
//  SOHJWT.m
//  SOHJWT
//
//  Created by soh335 on 2014/08/18.
//  Copyright (c) 2014年 soh335. All rights reserved.
//

#import "SOHJWT.h"
#import "SOHJWTAlgorithm.h"

NSString * const SOHJWTErrorDomain = @"io.github.soh335.sohjwt";

@implementation SOHJWT

+ (NSData *)encode:(NSDictionary *)header claims:(id)claims secret:(NSData *)secret error:(NSError **)error
{
    NSError *encodeErr = nil;
    
    NSString *alg = header[@"alg"];
    id<SOHJWTAlgorithmProtocol> algorithm = [self getAlgorithm:alg error:&encodeErr];
    
    if (encodeErr != nil) {
        if (error) {
            *error = encodeErr;
        }
        return nil;
    }
    
    NSMutableData *data = [NSMutableData data];
    
    NSData *encodedHeader = [NSJSONSerialization dataWithJSONObject:header options:0 error:&encodeErr];
    
    if (encodeErr != nil) {
        if (error) {
            *error = encodeErr;
        }
        return nil;
    }
    
    encodedHeader = [self encodeBase64UrlSafe:encodedHeader error:&encodeErr];
    
    if (encodeErr != nil) {
        if (error) {
            *error = encodeErr;
        }
        return nil;
    }
    
    NSData *encodedClaims = [NSJSONSerialization dataWithJSONObject:claims options:0 error:&encodeErr];
    
    if (encodeErr != nil) {
        if (error) {
            *error = encodeErr;
        }
        return nil;
    }
    
    encodedClaims = [self encodeBase64UrlSafe:encodedClaims error:&encodeErr];
    
    if (encodeErr != nil) {
        if (error) {
            *error = encodeErr;
        }
        return nil;
    }
    
    [data appendData:encodedHeader];
    [data appendData:[@"." dataUsingEncoding:NSUTF8StringEncoding]];
    [data appendData:encodedClaims];
    
    NSData *signature = [algorithm sign:secret data:data];
    
    signature = [self encodeBase64UrlSafe:signature error:&encodeErr];
    
    if (encodeErr != nil) {
        if (error) {
            *error = encodeErr;
        }
        return nil;
    }
    
    [data appendData:[@"." dataUsingEncoding:NSUTF8StringEncoding]];
    [data appendData:signature];
    
    return data;
}

+ (id)decode:(NSData *)jwt secret:(NSData *)secret error:(NSError **)error
{
    NSError *decodeErr = nil;
    
    NSString *str = [[NSString alloc] initWithData:jwt encoding:NSUTF8StringEncoding];
    NSArray *splitedStr = [str componentsSeparatedByString:@"."];
    
    if (splitedStr.count != 3) {
        // error
        decodeErr = [[NSError alloc] initWithDomain:SOHJWTErrorDomain code:SOHJWTErrorCodeInvalidSegumentCount userInfo:@{NSLocalizedDescriptionKey:@"invalid segument count"}];
        if (error) {
            *error = decodeErr;
        }
        return nil;
    }
    
    NSData *headerData = [self decodeBase64UrlSafe:splitedStr[0] error:&decodeErr];
    
    if (decodeErr != nil) {
        if (error) {
            *error = decodeErr;
        }
        return nil;
    }
    
    NSDictionary *header = [NSJSONSerialization JSONObjectWithData:headerData options:0 error:&decodeErr];
    
    if (decodeErr != nil) {
        if (error) {
            *error = decodeErr;
        }
        return nil;
    }
    
    NSData *claimsData = [self decodeBase64UrlSafe:splitedStr[1] error:&decodeErr];
    
    if (decodeErr != nil) {
        if (error) {
            *error = decodeErr;
        }
        return nil;
    }
    
    id claims = [NSJSONSerialization JSONObjectWithData:claimsData options:0 error:&decodeErr];
    
    if (decodeErr != nil) {
        if (error) {
            *error = decodeErr;
        }
        return nil;
    }
    
    NSString *alg = header[@"alg"];
    id<SOHJWTAlgorithmProtocol> algorithm = [self getAlgorithm:alg error:&decodeErr];
    
    if (decodeErr != nil) {
        if (error) {
            *error = decodeErr;
        }
        return nil;
    }
    
    NSData *signature = [self decodeBase64UrlSafe:splitedStr[2] error:&decodeErr];

    if (decodeErr != nil) {
        if (error) {
            *error = decodeErr;
        }
        return nil;
    }
    
    NSMutableData *data = [NSMutableData data];
    [data appendData:[splitedStr[0] dataUsingEncoding:NSUTF8StringEncoding]];
    [data appendData:[@"." dataUsingEncoding:NSUTF8StringEncoding]];
    [data appendData:[splitedStr[1] dataUsingEncoding:NSUTF8StringEncoding]];
    
    if (![algorithm verify:signature key:secret data:data]) {
        decodeErr = [[NSError alloc] initWithDomain:SOHJWTErrorDomain code:SOHJWTErrorCodeFailedVerify userInfo:@{NSLocalizedDescriptionKey:@"failed to verify"}];
        if (error) {
            *error = decodeErr;
        }
        return nil;
    }
    
    return claims;
}

#pragma mark - private

+ (id<SOHJWTAlgorithmProtocol>)getAlgorithm:(NSString *)alg error:(NSError **)error
{
    id<SOHJWTAlgorithmProtocol> algorithm = [[SOHJWTAlgorithm shared] getAlgorithm:alg];
    
    if (algorithm == nil) {
        *error = [[NSError alloc] initWithDomain:SOHJWTErrorDomain code:SOHJWTErrorCodeNotSupportAlgorithm userInfo:@{NSLocalizedDescriptionKey:@"not support algorithm"}];
        return nil;
    }
    
    return algorithm;
}

+ (NSData *)encodeBase64UrlSafe:(NSData *)data error:(NSError **)error
{
    NSError *encodeErr;
    NSString *encoded = [data base64EncodedStringWithOptions:0];
    
    NSRegularExpression *regexp = [NSRegularExpression regularExpressionWithPattern:@"=+\\z" options:0 error:&encodeErr];
    
    if (encodeErr != nil) {
        if (error) {
            *error = encodeErr;
        }
        return nil;
    }
    
    encoded = [regexp stringByReplacingMatchesInString:encoded options:0 range:NSMakeRange(0, encoded.length) withTemplate:@""];

    encoded = [encoded stringByReplacingOccurrencesOfString:@"+" withString:@"-"];
    encoded = [encoded stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    
    return [encoded dataUsingEncoding:NSUTF8StringEncoding];
}

+ (NSData *)decodeBase64UrlSafe:(NSString *)str error:(NSError **)error
{
    str = [str stringByReplacingOccurrencesOfString:@"-" withString:@"+"];
    str = [str stringByReplacingOccurrencesOfString:@"_" withString:@"/"];
    
    int expectLength = ceil(str.length/4.0) * 4.0;
    
    if (expectLength - str.length > 0) {
        str = [str stringByPaddingToLength:expectLength withString:@"=" startingAtIndex:0];
    }
    
    return [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

@end
