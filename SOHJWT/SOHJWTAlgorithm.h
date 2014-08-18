//
//  SOHJWTAlgorithm.h
//  SOHJWT
//
//  Created by soh335 on 2014/08/18.
//  Copyright (c) 2014年 soh335. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol SOHJWTAlgorithmProtocol <NSObject>

- (NSString *)name;
- (NSData *)sign:(NSData *)key data:(NSData *)data;
- (BOOL)verify:(NSData *)signature key:(NSData *)key data:(NSData *)data;

@end

@interface SOHJWTAlgorithm : NSObject

+ (instancetype)shared;
- (void)setAlgorithm:(id<SOHJWTAlgorithmProtocol>)algorithm;
- (id<SOHJWTAlgorithmProtocol>)getAlgorithm:(NSString *)name;

@end

@interface SOHJWTAlgorithmNone : NSObject <SOHJWTAlgorithmProtocol>

@end

@interface SOHJWTAlgorithmHmacSha256 : NSObject <SOHJWTAlgorithmProtocol>

@end
