//
//  SOHJWTTests.m
//  SOHJWTTests
//
//  Created by soh335 on 2014/08/18.
//  Copyright (c) 2014年 soh335. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "SOHJWT.h"

@interface SOHJWTTests : XCTestCase

@end

@implementation SOHJWTTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

- (void)testNilError
{
    id header = @{
                  @"alg":@"dame",
                  @"typ":@"JWT",
                  };
    
    id claims = @{
                  @"iss":@"joe",
                  @"exp":@1300819380,
                  @"http://example.com/is_root":@YES,
                  };
    
    NSData *encoded = [SOHJWT encodeWithHeader:header claims:claims secret:nil error:nil];
    
    XCTAssertNil(encoded);
}

- (void)testNone
{
    id header = @{
                  @"alg":@"none",
                  @"typ":@"JWT",
                  };
    
    id claims = @{
                  @"iss":@"joe",
                  @"exp":@1300819380,
                  @"http://example.com/is_root":@YES,
                  };
    
    NSError *error = nil;
    NSData *encoded = [SOHJWT encodeWithHeader:header claims:claims secret:nil error:&error];
    
    XCTAssertNil(error);
    
    NSString *encodedString = [[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding];

    NSLog(@"%@", encodedString);
    
    id decoded = [SOHJWT decode:encoded secret:[@"secret" dataUsingEncoding:NSUTF8StringEncoding] error:&error];
    
    XCTAssertNil(error);
    
    NSLog(@"%@", decoded);
    
    XCTAssertEqualObjects(decoded, claims);
}

- (void)testHmacSha256
{
    id header = @{
                  @"alg":@"HS256",
                  @"typ":@"JWT",
                  };
    
    id claims = @{
                  @"iss":@"joe",
                  @"exp":@1300819380,
                  @"http://example.com/is_root":@YES,
                  };
    
    NSError *error = nil;
    NSData *encoded = [SOHJWT encodeWithHeader:header claims:claims secret:[@"secret" dataUsingEncoding:NSUTF8StringEncoding] error:&error];
    
    XCTAssertNil(error);
    
    NSString *encodedString = [[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding];
    
    NSLog(@"%@", encodedString);
    
    id decoded = [SOHJWT decode:encoded secret:[@"secret" dataUsingEncoding:NSUTF8StringEncoding] error:&error];
    
    XCTAssertNil(error);
    
    NSLog(@"%@", decoded);
    
    XCTAssertEqualObjects(decoded, claims);
}

- (void)testHmacSha256InvalidSecret
{
    id header = @{
                  @"alg":@"HS256",
                  @"typ":@"JWT",
                  };
    
    id claims = @{
                  @"iss":@"joe",
                  @"exp":@1300819380,
                  @"http://example.com/is_root":@YES,
                  };
    
    NSError *error = nil;
    NSData *encoded = [SOHJWT encodeWithHeader:header claims:claims secret:[@"secret" dataUsingEncoding:NSUTF8StringEncoding] error:&error];
    
    XCTAssertNil(error);
    
    NSString *encodedString = [[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding];
    
    NSLog(@"%@", encodedString);
    
    id decoded = [SOHJWT decode:encoded secret:[@"dame" dataUsingEncoding:NSUTF8StringEncoding] error:&error];
    
    XCTAssertNotNil(error);
    
    XCTAssertNil(decoded);
}

- (void)testNonSupportAlgorithm
{
    id header = @{
                  @"alg":@"RS256",
                  @"typ":@"JWT",
                  };
    
    id claims = @{
                  @"iss":@"joe",
                  @"exp":@1300819380,
                  @"http://example.com/is_root":@YES,
                  };
    
    NSError *error = nil;
    [SOHJWT encodeWithHeader:header claims:claims secret:[@"secret" dataUsingEncoding:NSUTF8StringEncoding] error:&error];
    
    XCTAssertNotNil(error);
}

@end
