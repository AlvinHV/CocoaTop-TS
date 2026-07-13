#import <Foundation/Foundation.h>
#import "ProcessSnapshot.h"

NS_ASSUME_NONNULL_BEGIN

typedef void(^RHCommandCompletion)(NSString * _Nullable stdoutString,
                                   NSString * _Nullable stderrString,
                                   NSInteger exitCode);

@interface RootHelperManager : NSObject

@property (assign) struct CocoaTopProcessSnapshot *snapshot;
@property (assign) struct CocoaTopThreadSnapshot *threadSnapshot;

+ (instancetype)sharedManager;

/// Must call once (e.g. in application:didFinishLaunching…)
- (BOOL)startHelperWithPath:(NSString*)helperPath
                      error:(NSError**)outError;

/// Send a single-line command (will append “\n” if missing),
/// and invoke the completion block once you get a newline back.
/// If the helper crashes before replying, you’ll get exitCode < 0.
- (void)sendCommand:(NSString*)command
         completion:(RHCommandCompletion)completion;

/// Request the process list through its dedicated pipe pair.
- (void)requestProcessListWithCompletion:(RHCommandCompletion)completion;

/// Fetch all thread information for one process through the command channel.
- (void)requestThreadsForPID:(pid_t)pid completion:(RHCommandCompletion)completion;

/// Deliver a signal from the privileged helper.
- (void)sendSignal:(int)signal toProcess:(pid_t)pid completion:(RHCommandCompletion)completion;

/// Tear it down (closes pipes, kills helper)
- (void)stopHelper;

@end

NS_ASSUME_NONNULL_END
