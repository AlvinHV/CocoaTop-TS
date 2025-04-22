#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void(^RHCommandCompletion)(NSString * _Nullable stdoutString,
                                   NSString * _Nullable stderrString,
                                   NSInteger exitCode);

@interface RootHelperManager : NSObject

@property (assign) struct kinfo_proc *kp;

+ (instancetype)sharedManager;

/// Must call once (e.g. in application:didFinishLaunching…)
- (BOOL)startHelperWithPath:(NSString*)helperPath
                      error:(NSError**)outError;

/// Send a single-line command (will append “\n” if missing),
/// and invoke the completion block once you get a newline back.
/// If the helper crashes before replying, you’ll get exitCode < 0.
- (void)sendCommand:(NSString*)command
         completion:(RHCommandCompletion)completion;

/// Tear it down (closes pipes, kills helper)
- (void)stopHelper;

@end

NS_ASSUME_NONNULL_END
