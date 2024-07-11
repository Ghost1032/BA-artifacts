
function get_timestamp()
{
	var today = new Date();
	var timestamp = today.getFullYear() + '-' + (today.getMonth()+1) + '-' + today.getDate() + ' ' + today.getHours() + ":" + today.getMinutes() + ":" + today.getSeconds() + ":" + today.getMilliseconds();
	return timestamp;
}
var jbPaths = [
    "dropbear_rsa_host_key",
    "Library/LaunchDaemons/dropbear.plist",
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSetttings.app",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/Library/dpkg/info/kjc.checkra1n.mobilesubstraterepo.list",
    "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist",
    "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/Systetem/Library/LaunchDaemons/com.ikey.bbot.plist",
    "/bin/bash",
    "/bin/sh",
    "/bin/su",
    "/etc/apt",
    "/etc/apt/preferences.d/checkra1n",
    "/etc/ssh/sshd_config",
    "/pguntether",
    "/private/var/lib/apt",
    "/private/var/lib/apt/",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/binsshd",
    "/usr/lib/frida",
    "/usr/lib/frida/frida-agent.dylib",
    "/usr/libexec/cydia/firmware.sh",
    "/usr/libexec/sftp-server",
    "/usr/libexec/ssh-keysign",
    "/usr/sbin/frida-server",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/mobile/Media/.evasi0n7_installed",
    "/var/root/.bash_history",
    "/var/tmp/cydia.log",
    "/Applications/Backgrounder.app",
    "/Applications/Pirni.app",
    "/Applications/Terminal.app",
    "/Applications/biteSMS.app",
    "/Applications/iFile.app",
    "/Applications/iProtect.app",
    "/Library/MobileSubstrate/DynamicLibraries/SBSettings.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/SBSettings.plist",
    "/System/Library/LaunchDaemons/com.bigboss.sbsettingsd.plist",
    "/System/Library/PreferenceBundles/CydiaSettings.bundle",
    "/User/Library/SBSettings",
    "/etc/profile.d/terminal.sh",
    "/private/etc/profile.d/terminal.sh",
    "/private/var/lib/dpkg/info/cydia-sources.list",
    "/private/var/lib/dpkg/info/cydia.list",
    "/private/var/root/Media/Cydia",
    "/usr/bin/sbsettingsd",
    "/usr/lib/libhooker.dylib",
    "/private/etc/apt/trusted.gpg.d/*",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substrate",
    "/usr/libexec/cydia",
    "/private/etc/apt/sources.list.d/procursus.sources",
    "/private/etc/apt/sources.list.d/sileo.sources",
    "/var/lib/dpkg/info/cydia-sources.list",
    "/var/lib/dpkg/info/cydia.list",
    "/var/lib/dpkg/info/mobileterminal.list",
    "/var/lib/dpkg/info/mobileterminal.postinst",
    "/var/mobile/Library/SBSettings",
    "/Applications/SBSettings.app",
    "/usr/lib/libcycript.dylib",
    "/usr/local/bin/cycript",
    "/var/lib/apt",
    "/Applications/crackerxi.app",
    "/etc/alternatives/sh",
    "/etc/apt/",
    "/etc/apt/sources.list.d/cydia.list",
    "/etc/apt/sources.list.d/electra.list",
    "/etc/apt/sources.list.d/sileo.sourcs",
    "/etc/apt/undecimus/undecimus.list",
    "/jb/amfid_payload.dylib",
    "/jb/jailbreakd.plist",
    "/jb/libjailbreak.dylib",
    "/jb/lzma",
    "/jb/offsets.plists",
    "/Library/MobileSubstrate/CydiaSubstrate.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/*",
    "/private/var/cache/apt",
    "/private/var/log/syslog",
    "/private/var/tmp/frida-*.dylib",
    "/private/var/Users",
    "/usr/lib/libjailbreak.dylib",
    "/usr/libexec/sshd-keygen-wrapper",
    "/usr/share/jailbreak/injectme.plist",
    "/var/lib/dpkg/info/mobilesubstrate.dylib",
    "/var/log/apt",
    "/var/mobile/Library/Caches/com.saurik.Cydia/sources.list",
    "/.bootstrapped_electra",
    "/.cydia_no_stash",
    "/.installed_unc0ver",
    "/Library/MobileSubstrate/DynamicLibraries/Choicy.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/0Shadow.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/afc2dService.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/afc2dSupport.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-FrontBoard.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/AppSyncUnified-installd.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/ChoicySB.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/dygz.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/LiveClock.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/MobileSafety.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/RocketBootstrap.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/Veency.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/xCon.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/zorro.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/zzzzHeiBaoLib.dylib",
    "/Library/MobileSubstrate/DynamicLibraries/",
    "/usr/lib/libsubstrate.dylib/SSLKillSwitch2.dylib",
    "/usr/lib/libsubstrate.dylib/SSLKillSwitch2.plist",
    "/usr/lib/CepheiUI.framework/CepheiUI",
    "/usr/lib/substrate/SubstrateInserter.dylib",
    "/usr/lib/substrate/SubstrateLoader.dylib",
    "/usr/lib/substrate/SubstrateBootstrap.dylib",
    "/Library/MobileSubstrate/",
    "/Library/PreferenceBundles/SubstitutePrefs.bundle/",
    "/Library/PreferenceBundles/SubstitutePrefs.bundle/Info.plist",
    "/Library/PreferenceBundles/SubstitutePrefs.bundle/SubstitutePrefs",
    "/Library/PreferenceLoader/Preferences/SubstituteSettings.plist",
    "/private/etc/alternatives/sh",
    "/private/etc/apt",
    "/private/etc/apt/preferences.d/checkra1n",
    "/private/etc/apt/preferences.d/cydia",
    "/private/etc/clutch.conf",
    "/private/etc/clutch_cracked.plist",
    "/private/etc/dpkg/origins/debian",
    "/private/etc/rc.d/substitute-launcher",
    "/private/etc/ssh/sshd_config",
    "/private/var/cache/apt/",
    "/private/var/cache/clutch.plist",
    "/private/var/cache/clutch_cracked.plist",
    "/private/var/db/stash",
    "/private/var/evasi0n",
    "/private/var/lib/dpkg/",
    "/private/var/mobile/Library/Filza/",
    "/private/var/mobile/Library/Filza/pasteboard.plist",
    "/private/var/mobile/Library/Cydia/",
    "/private/var/mobile/Library/Preferences/com.ex.substitute.plist",
    "/private/var/mobile/Library/SBSettingsThemes/",
    "/private/var/MobileSoftwareUpdate/mnt1/System/Library/PrivateFrameworks/DictionaryServices.framework/SubstituteCharacters.plist",
    "/private/var/root/Documents/Cracked/",
    "/System/Library/PrivateFrameworks/DictionaryServices.framework/SubstituteCharacters.plist",
    "/usr/bin/scp",
    "/usr/bin/sftp",
    "/usr/bin/ssh-add",
    "/usr/bin/ssh-agent",
    "/usr/bin/ssh-keygen",
    "/usr/bin/ssh-keyscan",
    "/usr/bin/sinject",
    "/usr/include/substrate.h",
    "/usr/lib/cycript0.9/",
    "/usr/lib/cycript0.9/com/",
    "/usr/lib/cycript0.9/com/saurik/",
    "/usr/lib/cycript0.9/com/saurik/substrate/",
    "/usr/lib/cycript0.9/com/saurik/substrate/MS.cy",
    "/usr/libexec/filza/Filza",
    "/usr/libexec/substituted",
    "/usr/libexec/sinject-vpa",
    "/usr/lib/substrate/",
    "/usr/lib/TweakInject",
    "/usr/libexec/cydia/",
    "/usr/libexec/substrate",
    "/usr/libexec/substrated",
    "/var/cache/apt/",
    "/var/cache/clutch.plist",
    "/var/cache/clutch_cracked.plist",
    "/var/db/stash",
    "/var/evasi0n",
    "/var/lib/apt/",
    "/var/lib/cydia/",
    "/var/lib/dpkg/",
    "/var/mobile/Library/Filza/",
    "/var/mobile/Library/Filza/pasteboard.plist",
    "/var/mobile/Library/Cydia/",
    "/var/mobile/Library/Preferences/com.ex.substitute.plist",
    "/var/mobile/Library/SBSettingsThemes/",
    "/var/MobileSoftwareUpdate/mnt1/System/Library/PrivateFrameworks/DictionaryServices.framework/SubstituteCharacters.plist",
    "/var/root/Documents/Cracked/",
    "/var/stash",
    "/Library/Activator",
    "/Library/Flipswitch",
    "/Library/dpkg/",
    "/Library/Frameworks/CydiaSubstrate.framework/",
    "/Library/Frameworks/CydiaSubstrate.framework/Headers/",
    "/Library/Frameworks/CydiaSubstrate.framework/Headers/CydiaSubstrate.h",
    "/Library/Frameworks/CydiaSubstrate.framework/Info.plist",
    "/Library/LaunchDaemons/ai.akemi.asu_inject.plist",
    "/Library/LaunchDaemons/com.openssh.sshd.plist",
    "/Library/LaunchDaemons/com.rpetrich.rocketbootstrapd.plist",
    "/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
    "/Library/LaunchDaemons/com.tigisoftware.filza.helper.plist",
    "/Library/LaunchDaemons/dhpdaemon.plist",
    "/Library/LaunchDaemons/re.frida.server.plist",
    "/Library/MobileSubstrate/DynamicLibraries/Choicy.plist"
];
function hook_class_method(class_name, method_name)
{
	var hook = eval('ObjC.classes.'+class_name+'["'+method_name+'"]');
		Interceptor.attach(hook.implementation, {
			onEnter: function(args) {
			console.log("[*] [" + get_timestamp() + " ] Detected call to: " + class_name + " -> " + method_name);
            console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context,
                Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                .join('\n\t'));

            
		}
	});
}

function run_hook_all_methods_of_classes_app_only()
{
	console.log("[*] Started: Hook all methods of all app only classes");
	var free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer'])
    var copyClassNamesForImage = new NativeFunction(Module.findExportByName(null, 'objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer'])
    var p = Memory.alloc(Process.pointerSize)
    Memory.writeUInt(p, 0)
    var path = ObjC.classes.NSBundle.mainBundle().executablePath().UTF8String()
    var pPath = Memory.allocUtf8String(path)
    var pClasses = copyClassNamesForImage(pPath, p)
    var count = Memory.readUInt(p)
    var classesArray = new Array(count)
    for (var i = 0; i < count; i++)
    {
        var pClassName = Memory.readPointer(pClasses.add(i * Process.pointerSize))
        classesArray[i] = Memory.readUtf8String(pClassName)
		var className = classesArray[i]
        if(className.indexOf("AlertView") == -1){
            continue;
        }
        if(className.indexOf("Location") != -1){
            continue;
        }
        var whiteList = ["RCCS","XMP"]
        var flag = false
        for(var j = 0;j<whiteList.length;j++){
            if(className.indexOf(whiteList[j]) != -1){
                flag = true
                break
            }
        }
        if(!flag){
            continue;
        }

		if (ObjC.classes.hasOwnProperty(className))
		{
			console.log("[+] Class: " + className);
			//var methods = ObjC.classes[className].$methods;
			var methods = ObjC.classes[className].$ownMethods;
			for (var j = 0; j < methods.length; j++)
			{
				try
				{
					var className2 = className;
					var funcName2 = methods[j];
					console.log("[-] Method: " + methods[j]);
					hook_class_method(className2, funcName2);
					console.log("[*] [" + get_timestamp() + "] Hooking successful: " + className2 + " -> " + funcName2);
				}
				catch(err)
				{
					console.log("[*] [" + get_timestamp() + "] Hooking Error: " + err.message);
				}
			}
		}
    }
    free(pClasses)
	console.log("[*] Completed: Hook all methods of all app only classes");
}

function hook_all_methods_of_classes_app_only()
{
	setImmediate(run_hook_all_methods_of_classes_app_only)
}

function patch_class_method(class_name, method_name)
{
	var hook = eval('ObjC.classes.'+class_name+'["'+method_name+'"]');
	Interceptor.attach(hook.implementation, {
          onEnter: function(args) {
            //注意:有时args参数值在这里会是一个对象,如果函数返回值是字符串类型,为了更好理解则要这样写
            //这里假设args[2]是要记录的参数
            //ObjC.classes.NSString.stringWithString_(args[2])或者args[2].toString()或者ObjC.classes.NSString.stringWithString_(args[2]).toString()
            //具体情况需要测试下是上面这3种的哪种写法
            //dump args
            for (var i = 0; i < 10; i++) {
                console.log("arg["+i+"]:"+args[i]);
            }
            console.log("param:"+args[2]+" type:"+typeof args[2]);
          },
          onLeave: function(retval) {
            //注意:retval一般会返回一个对象,如果函数返回值是字符串类型,为了更好理解则要这样写
            //ObjC.classes.NSString.stringWithString_(retval)或者retval.toString()或者ObjC.classes.NSString.stringWithString_(retval).toString()
            //具体情况需要测试下是上面这3种的哪种写法
            console.log("Return value-> (type:"+typeof retval+",value:"+retval+")");
            //retval.replace(0x00);
          }
        });
}
function patch_class_method_impl(class_name, method_name){
    var hook = eval('ObjC.classes.'+class_name+'["'+method_name+'"]');
    hook.implementation = ObjC.implement(hook, function(self, sel) {
        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context,
            Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            .join('\n\t'));
        console.log("["+class_name+method_name+"]"+" hooked");
        return ptr(0);
    });
}
function patch_class_method_impl_silence(class_name, method_name){
    var hook = eval('ObjC.classes.'+class_name+'["'+method_name+'"]');
    hook.implementation = ObjC.implement(hook, function(self, sel) {
        //console.log("["+class_name+method_name+"]"+" hooked");
        return ptr(0);
    });
}
var hook = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        this.jailbreak_detection = false;
        var path = ObjC.Object(args[2]).toString();
        var i = jbPaths.length;
        while (i--) {
            if (jbPaths[i] == path) {
                //console.log("Jailbreak detection => Trying to read path: " + path);
                this.jailbreak_detection = true;
            }
        }
    },
    onLeave: function(retval) {
        if (this.jailbreak_detection) {
            retval.replace(0x00);
            //console.log("Jailbreak detection bypassed!");
        }
    }
});



//patch_class_method("BCESCheckerFrida","- isFridaServerListenOnDefaulPort");
//patch_class_method_impl_silence("BCESCheckerFrida","- isFridaDylibFileExist");

//patch_class_method("BCESCheckerFrida","- isGumjsThreadExist");

patch_class_method_impl_silence("BCESRoot","- statChecking");
patch_class_method_impl_silence("BCESRoot","- dangerousEnvs");
patch_class_method_impl_silence("BCESRoot","- dangerousLinkFiles");
patch_class_method_impl_silence("BCESRoot","- getJailbreakInfos");
patch_class_method_impl_silence("BCESRoot","- jailbreakTools");
patch_class_method_impl_silence("BCESRoot","- dangerousImages");
patch_class_method_impl_silence("BCESRoot","- writablePaths");

hook_specific_method_of_class("BCESInformation","+ isRoot")
hook_specific_method_of_class("BCEInfomartion","+ isRoot")
hook_specific_method_of_class("TMFJSBridgeInvocation_GetIsRoot","- checkDylibs")
hook_specific_method_of_class("TMFJSBridgeInvocation_GetIsRoot","- invokeWithParameters:")
patch_class_method_impl_silence("BCESCheckerStartInfo","- check")
patch_class_method_impl_silence("BCESCheckerDeviceReuse","- check")
patch_class_method_impl_silence("BCESCheckerHttps","- check")
patch_class_method_impl_silence("BCESCheckerFrida","- check")
patch_class_method_impl_silence("BCESCheckerEnvironment","- check")
patch_class_method_impl_silence("BCESCheckerInject","- check")
patch_class_method_impl_silence("BCESCheckerApp","- check")
patch_class_method_impl_silence("BCESCheckerStart","- check")
patch_class_method_impl_silence("BCESCheckerEmulator","- check")
//patch_class_method_impl_silence("BCESCheckerFrida","+ name");
//patch_class_method_impl_silence("BCESCheckerKeepAlive","- check")
patch_class_method_impl_silence("BCESCheckerUserData","- check")
patch_class_method_impl_silence("BCECheckerEnvironment","- initWithCheckRoot:checkRiskFrame:")
//patch_class_method_impl_silence("BCECheckerEnvironment","- initWithCheckRoot:checkRiskFrame:checkFrida:")
patch_class_method_impl_silence("BCESCheckerHost","- check")
patch_class_method_impl_silence("BCESCheckerProxy","- check")
patch_class_method_impl_silence("BCESCheckerDebug","- check")
patch_class_method_impl("BCECheckerSendHelper","+ sendToUploadWithChecker:andMessage:")
patch_class_method_impl_silence("BCECheckerProcesses","- check")
patch_class_method_impl_silence("BCECheckerDevice","- check")
patch_class_method_impl_silence("BCECheckerStart","- check")
patch_class_method_impl_silence("BCECheckerEnvironment","- check")
patch_class_method_impl_silence("BCECheckerSelfProcess","- check")
patch_class_method_impl_silence("BCECheckerUserData","- check")
patch_class_method_impl_silence("BCESCheckerProcesses","- check")
patch_class_method_impl_silence("BCECheckerLocation","- check")
//patch_class_method_impl_silence("BCECheckerInject","- check")
patch_class_method_impl_silence("BCECheckerEmulator","- check")
patch_class_method_impl_silence("BCECheckerDebug","- check")
patch_class_method_impl_silence("BCECheckerDeviceReuse","- check")
patch_class_method_impl_silence("UIDevice","- isJailbroken")
patch_class_method_impl_silence("BangcleCheck","- initializeBangcleSecureUtiltil")
patch_class_method_impl_silence("BangcleCheck","- showJailbreakAlert")
patch_class_method_impl_silence("XMLogonController","- showAlertViewWithTitle:message:")
patch_class_method_impl_silence("BCESRiskStub","+ alertForEvent:withAction:")
patch_class_method_impl_silence("RiskStub","+ alertForEvent:withAction:")
patch_class_method_impl_silence("RiskStub","+ initAlertActionFromBundleData:");
patch_class_method_impl_silence("UPWHomePageUtils","+ showJailBrokenAlertIfNeeded")
//patch_class_method_impl_silence("BCEThreadScheduler","- fireChecker:")
//patch_class_method_impl_silence("BCESThreadScheduler","- fireChecker:")
patch_class_method_impl("BCESCheckerEnvironment","- handleNotificationOfProcesses:")
patch_class_method_impl("BOCAlertView","- initWithTitle:message:errCode:cancleBtn:sureBtn:")
patch_class_method_impl("BOCAlertView","- initWithTitle:message:hlmessage:errCode:cancleBtn:sureBtn:")
patch_class_method_impl("BOCAlertView","- showBOCAlertView")
patch_class_method_impl("BCMAuthAlertView", "- init")
patch_class_method_impl("BOCAlertView","- alertView")
patch_class_method_impl("BCEUIAlertAction","- init")
patch_class_method_impl("zqfwgkVfsGXkrMsD","+ protect")
patch_class_method_impl("XMSecurityController","- alertView:clickedButtonAtIndex:")
//patch_class_method_impl("BCMAuthManager","- showAlertViewWithType:forceAlert:")
//patch_class_method_impl("Environment","- showAlertInWindowWithText:")
function patch_class_method_bool(class_name, method_name){
    var hook = eval('ObjC.classes.'+class_name+'["'+method_name+'"]');
    hook.implementation = ObjC.implement(hook, function(self, sel) {
        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context,
            Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            .join('\n\t'));
        console.log("["+class_name+method_name+"]"+" hooked");
        return ptr(0x1);
    });
}
patch_class_method_bool("BCESRiskStub","+ isIncludeInWhiteList")
patch_class_method_impl("TDRAlertViewController","- initWithTitle:message:cancelTitle:otherTitle:")
patch_class_method_impl("UPForbbidenViewController","- initWithTitle:startPage:")
patch_class_method_impl("DocumentOutlineEntry","- initWithTitle:target:level:")
patch_class_method_impl("BOCAlertView","- sureBtn")
function hook_specific_method_of_class(className, funcName)
{
  var iOSObjCallStr = "className=" + className + ", funcName=" + funcName
  console.log("iOSObjCallStr=", iOSObjCallStr)
  var curClass = ObjC.classes[className];
  if (typeof(curClass) !== 'undefined') {
    var curMethod = curClass[funcName];
    if (typeof(curMethod) !== 'undefined') {

      Interceptor.attach(curMethod.implementation, {
        onEnter: function(args) {
          console.log("==================== " + iOSObjCallStr + " ====================");
          // args[0] is self = id
          const argSelf = args[0];
          console.log("argSelf: ", argSelf);
          const argSelfObj = new ObjC.Object(argSelf);
          console.log("argSelfObj: ", argSelfObj);
          const argSelfClassName = argSelfObj.$className;
          console.log("argSelfClassName: ", argSelfClassName);

          // args[1] is selector
          const argSel = args[1];
          console.log("argSel: ", argSel);
          const argSelStr = ObjC.selectorAsString(argSel);
          console.log("argSelStr: ", argSelStr);

            // args[2] holds the first function argument
            const args2 = args[2];
            console.log("args2: ", args2);
            if (args2 != 0x0) {
              const args2Obj = new ObjC.Object(args2);
              // const args2Obj = new ObjC.Object(ptr(args2));
              console.log("args2Obj: ", args2Obj);
              const args2ObjClassName = args2Obj.$className;
              console.log("args2ObjClassName: ", args2ObjClassName);
              const args2ObjStr = args2Obj.toString();
              console.log("args2ObjStr: ", args2ObjStr);
              if(args2ObjStr.indexOf("deviceRootStatus") != -1){
                console.log("deviceRootStatusdeviceRootStatusdeviceRootStatusdeviceRootStatusdeviceRootStatusdeviceRootStatus");
                //modify the arg
                args[2] = ptr(0x0);
                //cancel the call
                return;
              }
            }
            
            const args3 = args[3];
            console.log("args3: ", args3);
            if (args3 != 0x0) {
              const args3Obj = new ObjC.Object(args3);
              console.log("args3Obj: ", args3Obj);
              const args3ObjClassName = args3Obj.$className;
              console.log("args3ObjClassName: ", args3ObjClassName);
              const args3ObjStr = args3Obj.toString();
              console.log("args3ObjStr: ", args3ObjStr);
            }
            for(var i=3;i<10;i++){
                console.log("args["+i+"]:"+args[i]);
                const argsi = args[i];
                if (argsi != 0x0) {
                    const argsiObj = new ObjC.Object(argsi);
                    console.log("argsiObj: ", argsiObj);
                    const argsiObjClassName = argsiObj.$className;
                    
                    console.log("argsiObjClassName: ", argsiObjClassName);
                    
                    const argsiObjStr = argsiObj.toString();
                    console.log("argsiObjStr: ", argsiObjStr);
                    if(argsiObjStr.indexOf("deviceRootStatus") != -1){
                        console.log("deviceRootStatusdeviceRootStatusdeviceRootStatusdeviceRootStatusdeviceRootStatusdeviceRootStatus");
                    
                        //modify the arg
                        args[i] = ptr(0x0);
                        //cancel the call
                        return;
        
                    }
                }
            }

        }
      });
    }else{
      console.log("Can't find method", funcName);
    }
  }else{
    console.log("Can't find class: ", className);
  }
}

//Your class name  and function name here
//hook_class_method("TMFJSBridgeInvocation_deviceRootStatus","- invokeWithParameters:")
// hook_specific_method_of_class("TMFJSBridge","- invokeWithFunction:params:pageId:invokeId:callbackCompletion:completionHandler:")
//hook_class_method("UIAlertView","- initWithTitle:message:delegate:cancelButtonTitle:otherButtonTitles:")
//hook_class_method("UIButton","+ buttonWithType:")
//hook_class_method("WKWebView","+ alloc")

//hook_all_methods_of_classes_app_only()
run_hook_all_methods_of_classes_app_only()
