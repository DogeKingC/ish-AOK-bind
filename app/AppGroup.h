//
//  AppGroup.h
//  iSH
//
//  Created by Theodore Dubois on 2/28/20.
//

#import <Foundation/Foundation.h>

NSURL *ContainerURL(void);
// True when the container is a real App Group (and so the File Provider
// extension exists). False on a sideloaded build, where ContainerURL() falls
// back to the app's own Documents directory.
bool ContainerIsAppGroup(void);
int ISHAppGroupAcquireNamedLock(NSString *category, NSString *name, BOOL exclusive, NSError **error);
int ISHAppGroupTryAcquireNamedLock(NSString *category, NSString *name, BOOL exclusive, NSError **error);
void ISHAppGroupReleaseLock(int fd);
