---
layout: post
title: Unauthd - Logic bugs FTW
---

## Introduction 

Hi! I'm Ilias aka A2nkF, an independent security researcher from Germany.

This blog post is about a MacOS LPE chain I wrote and reported back in Februray. It features three logic bugs to go from user to root with System Integrety Protection (SIP) bypass to kernel. Since I'm not exploiting any memory corruptions or other vulnerabilites that aren't 100% deterministic, this chain is fully reliable which I think is cool ;). It runs on MacOS <= 10.15.5
This was my first real life exploit chain so I probably made a ton of mistakes. If you spot any or have any suggestions/improvments, please DM me on [twitter](https://twitter.com/A2nkF_) or create a pull request/issue. 


## Vulnerability 1

The first vulnerability lies within `authd(8)`, which is part of the mostly open source [Security.framework](https://opensource.apple.com/source/Security/Security-59306.11.20/OSX/). This 
framework manages, as the name indicates, security related things including Keychain accesses
(through `securityd(1)`), Code signing (through `trustd(8)`) and **authorization, authentication and spawning privileged processes (through `authd`)**. 

There are [some facilities](https://developer.apple.com/documentation/security/authorization_services) to interact with `authd` offered by the security framework. These APIs can be used by third party applications, but they are also used by a lot of Apple's own private and public frameworks to perform privileged actions from within an unprivileged process.

The following graphic tries to illustrate the functionality provided by `authd`.


![_config.yml]({{ site.baseurl }}/images/unauthd_Logic_bugs_FTW/process_authd.png)

The set of supported rules as well as some preregistered rights are defined in the [authorization.plist](https://opensource.apple.com/source/Security/Security-59306.11.20/OSX/authd/authorization.plist.auto.html). The rules allow for very granular control over which privilege a client needs to have in order to qualify for a rule. They include but are not limited to the client's group, the client's user, whether it's running as GUI or console and the client's entitlements. Some rights additionally or alternatively require the user to enter their password into a pop-up dialog. If you're a MacOS user, I'm sure you've seen similar pop-ups before ;)

![_config.yml]({{ site.baseurl }}/images/unauthd_Logic_bugs_FTW/authd_popup.png)

While auditing the `authd` code I found something interesting in [process.c](https://opensource.apple.com/source/Security/Security-59306.11.20/OSX/authd/process.c.auto.html).
Specifically, the lines of Code responsible for fetching code signing related information from a client: 

```c
    // ...

    status = SecCodeCopySigningInformation(codeRef, kSecCSRequirementInformation, &code_info); // [1]
    require_noerr_action(status, done, os_log_debug(AUTHD_LOG, "process: PID %d SecCodeCopySigningInformation failed with %d", proc->auditInfo.pid, (int)status));

    // ...
    
    if (CFDictionaryGetValueIfPresent(code_info, kSecCodeInfoEntitlementsDict, &value)) {
        if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
            proc->code_entitlements = CFDictionaryCreateCopy(kCFAllocatorDefault, value); // [2]
        }
        value = NULL;
    }
```

As we can see, it calls `SecCodeCopySigningInformation` to retrieve the data from the client `[1]`
and if it finds any entitlements, it proceeds to copying the values from said entitlements into a dict `[2]`.

Ok, so what's the issue here?

At first glance this code seems fine, but reading Apple's developer documentation for `SecCodeCopySigningInformation` reveals the problem:

```
 If the signing data for the code is corrupt or invalid, this function may fail or it 
 may return partial data. To ensure that only valid data is returned (and errors are 
 raised for invalid data), you must successfully call the SecCodeCheckValidity or 
 SecCodeCheckValidityWithErrors function before calling SecCodeCopySigningInformation.
```

Well... neither one gets called before calling `SecCodeCopySigningInformation` -.- BTW The copyright on this file dates to 2012-2013!

The `SecCodeCheckValidity[WithErrors]` functions would compare the client's binary on disk to its CDHash, verifying its integrity. Since this never happens, it's possible to codesign the client with arbitrary entitlements without `authd` ever complaining.

Now we need to figure out what entitlements `authd` is interested in. This is the function `authd` uses internally to check whether a process has the required entitlements for a right: 

```c
bool
process_has_entitlement_for_right(process_t proc, const char * right)
{
    bool entitled = false;
    require(right != NULL, done);

    CFTypeRef rights = NULL;
    if (proc->code_entitlements && CFDictionaryGetValueIfPresent(proc->code_entitlements, CFSTR("com.apple.private.AuthorizationServices"), &rights)) { // [3]
        if (CFGetTypeID(rights) == CFArrayGetTypeID()) {
            CFStringRef key = CFStringCreateWithCStringNoCopy(kCFAllocatorDefault, right, kCFStringEncodingUTF8, kCFAllocatorNull);
            require(key != NULL, done);
            
            CFIndex count = CFArrayGetCount(rights);
            for (CFIndex i = 0; i < count; i++) {
                if (CFEqual(CFArrayGetValueAtIndex(rights, i), key)) {
                    entitled = true;
                    break;
                }
            }
            CFReleaseSafe(key);
        }
    }
    
done:
    return entitled;
}
```

As we can see, it looks for the `com.apple.private.AuthorizationServices` entitlement `[3]` which is supposed to be an array of strings where each entry is the name of a desired right.

With this knowledge, triggering the bug is very straight forward:

1. Create an entitlement file with the right(s) you want (we'll use `system.install.apple-software` for the sake of demonstation) e.g.: 

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.private.AuthorizationServices</key>
    <array>  
        <string>system.install.apple-software</string>
    </array>
</dict>
</plist>
```

2. Write a program that waits for some time, then creates an `AuthorizationRef` and requests the desired right from `authd`
3. While the program is waiting, run `codesign -f -s - --entitlements entitlements.xml ./test` where `./test` is the path to your program
4. Observe the `authd` logs. You'll find something similar to this:

![_config.yml]({{ site.baseurl }}/images/unauthd_Logic_bugs_FTW/log_authd.png)

In case you're wondering why we can't just do the codesigning first, before even running the program, it's because of the AppleMobileFileIntegretyDaemon or `amfid(8)`. This is the daemon responsible for fetching and verifying entitlements/signatures of signed binaries. `amfid` wouldn't allow us to run since we're a non Apple signed program with restricted entitlements.

This would be an awesome primitive, if we could get any right we wanted just by holding the proper entitlement, in which case we could just get the `system.privilege.admin` right and use the `AuthorizationExecuteWithPrivileges` API to get root privileges, however that's not the case. 
As mentioned earlier, a process needs to satisfy the rules in order to obtain a right. One of these rules (mostly used by Apple's private frameworks) checks the entitlements, however many rules don't care about the entitlements. Instead they require the client to run as a specific user or the user to enter a password. 

After analyzing the authorization.plist I found the following rights to be obtainable by the default user just by holding the corresponding entitlements: 

```
Right                                        Private Framework implementing API

system.install.apple-software               // PackageKit.framework/InstallKit.framework
system.preferences.nvram                    // SystemAdministrator.framework
com.apple.uninstalld.uninstall              // Uninstall.framework
com.apple.opendirectoryd.linkidentity
com.apple.ServiceManagement.daemons.modify  // ServiceManagement.framework
system.services.directory.configure
com.apple.trust-settings.user
system.install.apple-config-data            // PackageKit.framework/InstallKit.framework
system.services.networkextension.filtering
system.install.software.iap                 // PackageKit.framework/InstallKit.framework
system.install.software.mdm-provided        // PackageKit.framework/InstallKit.framework
system.install.apple-software.standard-user // PackageKit.framework/InstallKit.framework
system.services.systemconfiguration.network
com.apple.activitymonitor.kill              // Activicymonitor?
com.apple.XType.fontmover.restore
com.apple.security.assessment.update
system.services.networkextension.vpn
com.apple.SoftwareUpdate.scan               // SoftwareUpdate.framework/InstallKit.framework
com.apple.SoftwareUpdate.modify-settings    // SoftwareUpdate.framework/InstallKit.framework
system.preferences.security.remotepair
```

These are quite a few rights. Three that immediately sparked my interest were `system.install.apple-software`, `system.preferences.nvram` and `com.apple.ServiceManagement.daemons.modify`. Sadly the `SystemAdministrator.framework` itself performs additional checks on the client, so we can't write nvram and the `com.apple.ServiceManagement.daemons.modify` right sounds a bit more promising than it actually is. It doesn't allow the registration of daemons, but only the starting/stopping of existing ones. 

Honorable mentions are `com.apple.activitymonitor.kill` which can be used to kill arbitrary processes and `com.apple.uninstalld.uninstall` that can be used to remove files/applications without the user entering their password. These two could easily be used to crash the system, but that's not what we want. We want kernel code execution :P 

So we're left with the `system.install.*` rights. Reversing the private `PackageKit.framework` revealed that it has some interesing APIs. They can be used to install Apple signed packages to any non-SIP protected location. That'll get useful when we get to the next vulnerability :P

I'm sure that I've missed some other way to use the rights to get code execution. If you're interested, feel free to do some reversing of your own and please tell me what you find out ;).

Apple's mitigation for this bug was implementing the code validity checks in `SecCodeCopySigningInformation`, thereby removing the need to call `SecCodeCheckValidity[WithErrors]` beforehand.
The updated developer documentation states:

```
This function obtains and verifies the signature on the code specified by the code object. 
It checks the validity of all sealed components, including resources (if any). It validates the code against 
a code requirement if one is specified. The call succeeds if all these conditions are satisfactory.
```

## Vulnerability 2

Up until now, we're able to install an Apple signed package to any location. So we bypassed the password prompt you'd usually see when installing packages, but we're limited to Apple signed ones. 

This can't be that bad, can it? ... Spoiler, it can. :) 

PKG files are basically archives that include the files to be installed, an optional code signature and pre/post-install scripts. The `pkgutil(1)` utility can be used to unveil the contents of such an archive. 

Generally, pre/post-install scripts are executed by `installd(8)`, which runs as root. But we can't build our own package with malicious scripts, since it wouldn't be Apple 
signed... So, what if we found an Apple signed package, where we can somehow hijack one of these scripts? That would be even better than crafting our own package, because if a package is signed by Apple, the scripts aren't executed by `installd` but `system_installd(8)`! The difference is that `system_installd` holds the `com.apple.rootless.install.heritable` entitlement. This means that it **and all its child processes** run without SIP restrictions, which makes sense because they probably have to install or update system files at SIP protected locations. 

So where can we get Apple signed packages? There are quite a few at [Apple's developer website](https://developer.apple.com/download/more/), but after downloading all of them and reading through most of the scripts I didn't manage to find anything... Since this wasn't successful I looked for alternative downloads and finally found one: [`macOSPublicBetaAccessUtility.pkg`](https://beta.apple.com/sp/downloads/projects/1001260/downloads/1012439) downloadable at beta.apple.com. Let's have a look at this postinstall script, `$3` holds the disk, this package is being installed onto:  

![_config.yml]({{ site.baseurl }}/images/unauthd_Logic_bugs_FTW/systeminstalld_script.png)

So here we are, being able to forge an executable with elevated rights as long as the path matches. Uhm, I don't know why anyone would ever do something like this but whatever, we have our root code execution and a SIP bypass for good measure. 
Now, we still want kernel code execution, so on to the next vulnerability :P


## Vulnerability 3

The rather obvious target to get kernel code execution, when we already have a SIP bypass and code execution as root is `kextutil(8)`. This is the utility, responsible for loading/unloading kernel extensions. On systems with SIP disabled, it's sufficient to be root if you want to load a kernel extension. However on systems with SIP, you can only load kernel extensions that are signed by Apple. 
For some reason the signature validation doesn't happen in the kernel, but in `kextutil` itself!? SIP restricts root from debugging system processes like `kextutil` so we can't just make it skip the signature checking. 
But there is something else we can do. When instructing `kextutil` to load a kernel extension it does the following things. First, it copies the kernel extension to a SIP protected directory (`/Library/StagedExtensions/private/<path to kext>` e.g. kext at `/tmp/test.kext` would be copied to `/Library/StagedExtensions/private/tmp/test.kext`) to ensure that no one tampers with it while it's being verified :P Then it verifies the kext's signature and then it proceeds to loading and starting it.

In theory, this could be fine, if kextutil would open the kext just once, loading all the files, performing the checks and then load the files from memory. The usage of file descriptors could mitigate this issue, but in reality, there is a race condition between when the kext is being verified and when it's being loaded into the kernel.

But as I mentioned in the introduction, this chain is 100% reliable and most race conditions have some chance of you loosing the race. This is where we can use a trick to ensure that we always win the race: `kextutil` has an `-interactive` flag. Specifying this flag will stop `kextutil` at each of the previously discussed steps, allowing us to win the "race" 100% of the time. 

So this is what we need to do after bypassing SIP: 

1. Copy some Apple signed kernel extension (e.g.`acfs.kext`) to a non-SIP protected location (e.g. `/tmp`)
2. Run `kextutil -interactive /tmp/acfs.kext` (`kextutil` will automatically verify the signature but wait for your interaction before loading the kext)
3. Overwrite the binary with your own (e.g. `mv kernelHax /Library/StagedExtensions/private/tmp/acfs.kext/Contents/MacOS/acfs`)
4. Tell `kextutil` to continue. It will load the kext including our malicious code into the kernel
5. Tell `kextutil` to continue again. This will make it start the kernel extension

## Demo time \o/

Here is a video of the chain in action:

<iframe title="vimeo-player" src="https://player.vimeo.com/video/443500253" width="640" height="400" frameborder="0" allowfullscreen></iframe>

## Conclusion

There are a lot of bugs out there, in widely used software and some are not as complicated as one might think. I personally learned a bunch of new things, since I never had to connect multiple vulnerabilities into a single chain and maybe you also learned a thing or two. And if that's not the case, I hope these bugs were at least entertaining :).

The full exploit chain can be found [here](https://github.com/A2nkF/unauthd). Feel free to DM me on [twitter](https://twitter.com/A2nkF_) or send me an email (`"A2nkF@notADomain.xyz".replace('notADomain.xyz','protonmail.com')`) if you have any questions, improvements or just want to chat ;)


## Timeline

January 1st 2020: Initial Discovery

February 24th 2020: First working Exploit

February 28th 2020: Reported Vulnerabilies to Apple

July 24th 2020: Apple released public patch

July 31st 2020: Public Disclosure

~ Ilias Morad (A2nkF)