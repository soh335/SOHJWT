//
//  SOHJWT.h
//  SOHJWT
//
//  Created by soh335 on 2014/08/18.
//  Copyright (c) 2014年 soh335. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef enum SOHJWTErrorCode : NSUInteger {
    SOHJWTErrorCodeInvalidSegumentCount = 1,
    SOHJWTErrorCodeFailedVerify,
    SOHJWTErrorCodeNotSupportAlgorithm,
} SOHJWTErrorCode;

@interface SOHJWT : NSObject

+ (NSData *)encodeWithHeader:(NSDictionary *)header claims:(id)claims secret:(NSData *)secret error:(NSError **)error;
+ (id)decode:(NSData *)jwt secret:(NSData *)secret error:(NSError **)error;

@end
