
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
        var whiteList = ["ADADADA"]
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
            retval.replace(1);
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




function patch_class_method_bool(class_name, method_name){
    var hook = eval('ObjC.classes.'+class_name+'["'+method_name+'"]');
    hook.implementation = ObjC.implement(hook, function(self, sel) {
        console.log("["+class_name+method_name+"]"+" hooked");
        return 0x00;
    });
}

function occurrences(string, subString, allowOverlapping) {
    // console.log("string=" + string + ",subString=" + subString + ", allowOverlapping=" + allowOverlapping)
    string += "";
    subString += "";
    if (subString.length <= 0) return (string.length + 1);

    var n = 0,
        pos = 0,
        step = allowOverlapping ? 1 : subString.length;

    while (true) {
        pos = string.indexOf(subString, pos);
        // console.log("pos=" + pos)
        if (pos >= 0) {
            ++n;
            pos += step;
        } else break;
    }

    return n;
}

// convert from frida function call to ObjC function call
// "NSURL", "- initWithString:" => "-[NSURL initWithString:]"
function toiOSObjcCall(class_name, method_name){
    const instanceCallStart = "-[" + class_name + " ";
    const classCallStart = "+[" + class_name + " ";
    var objcFuncCall = method_name.replace("- ", instanceCallStart);
    objcFuncCall = objcFuncCall.replace("+ ", classCallStart);
    objcFuncCall = objcFuncCall + "]";
    // console.log(class_name + " -> " + method_name + " => " + objcFuncCall);
    return objcFuncCall;
}

/*******************************************************************************
* Frida Hook
*******************************************************************************/

// https://github.com/noobpk/frida-ios-hook/blob/master/frida-ios-hook/frida-scripts/hook-specific-method-of-class.js
function hook_specific_method_of_class(className, funcName)
{
    
  var iOSObjCallStr = toiOSObjcCall(className, funcName)
  console.log("iOSObjCallStr=", iOSObjCallStr)
  var curClass = ObjC.classes[className];
  if (typeof(curClass) !== 'undefined') {
    var curMethod = curClass[funcName];
    if (typeof(curMethod) !== 'undefined') {

      Interceptor.attach(curMethod.implementation, {
        onEnter: function(args) {
            console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context,
                Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
                .join('\n\t'));
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

          const argCount = occurrences(argSelStr, ":");
          console.log("argCount: ", argCount);

          // console.log("funcName=", funcName);
          // const argCount = occurrences(funcName, ":");
          // console.log("argCount: ", argCount);

          for (let curArgIdx = 0; curArgIdx < argCount; curArgIdx++) {
            const curArg = args[curArgIdx + 2];

            // const usePtr = false;
            const usePtr = true;
            if (usePtr) {
              // console.log("usePtr=", usePtr);
              const curArgPtr = ptr(curArg);
              console.log("---------- [" + curArgIdx + "] curArgPtr=" + curArgPtr);
              if (!curArgPtr.isNull()) {
                const curArgPtrObj = new ObjC.Object(curArgPtr);
                console.log("curArgPtrObj: ", curArgPtrObj);
                console.log("curArgPtrObj className: ", curArgPtrObj.$className);
                console.log("curArgPtrObj kind: ", curArgPtrObj.$kind);
              }
            } else {
              console.log("---------- [" + curArgIdx + "] curArg=" + curArg);
              if (curArg && (curArg != 0x0)) {
                // console.log("curArg className: ", curArg.$className);
                const curArgObj = new ObjC.Object(curArg);
                console.log("curArgObj: ", curArgObj);
                console.log("curArgObj className: ", curArgObj.$className);
                console.log("curArgObj kind: ", curArgObj.$kind);
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
var modules = Process.enumerateModules();
for(var i=0;i<modules.length;i++){
		console.log(`== Name: ${modules[i].name}  <${modules[i].base}>`);
}
/**
* 根据module名字和目标方法的偏移地址获得方法的绝对地址
*/
function get_func_addr(module, offset) {
    // 根据名字获取module地址
    var base_addr = Module.findBaseAddress(module);
    console.log("base_addr: " + base_addr);
  
    console.log(hexdump(ptr(base_addr), {
              length: 16,
              header: true,
              ansi: true
    }));
  
    var func_addr = base_addr.add(offset);
    if (Process.arch == 'arm')
       return func_addr.add(1);  //如果是32位地址+1
    else
       return func_addr;
 }

// 获取目标函数的绝对地址
//var func_addr = get_func_addr('MbapMPaaS', 0x1036F92BC);
//console.log('func_addr: ' + func_addr);
/*
Interceptor.attach(ptr(func_addr), {
    onEnter: function(args) {
        console.log("====onEnter=====");
        console.log("arg0: " + args[0]);
        console.log(hexdump(ptr(args[0]), {
            length: 64,
            header: false,
            ansi: false
        }))
        console.log("arg1: " + args[1]);
        console.log("arg2: " + args[2]);
    },
    onLeave: function(retval) {
        console.log("====onLeave=====");
        console.log("arg0: " + retval);
        console.log(hexdump(ptr(retval), {
            length: 64,
            header: true,
            ansi: true
        }))
    }
});
*/
var hook = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        this.jailbreak_detection = false;
        /*
        console.log('\tBacktrace:\n\t' + Thread.backtrace(this.context,
            Backtracer.ACCURATE).map(DebugSymbol.fromAddress)
            .join('\n\t'));
            */
        var path = ObjC.Object(args[2]).toString();
        var i = jbPaths.length;
        while (i--) {
            if (jbPaths[i] == path) {
                console.log("Jailbreak detection => Trying to read path: " + path);
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

//patch_class_method_impl("UIAlertController","- addAction:")
//fuckUIActionButton()
// 使用 Frida 的 Objective-C 桥接
ObjC.schedule(ObjC.mainQueue, function() {
    // 拦截 UIAlertController 的 addAction: 方法
    const UIAlertController = ObjC.classes.UIAlertController;
    const originalAddAction = UIAlertController['- addAction:'];
  
    // 替换原有的 addAction: 方法
    Interceptor.replace(originalAddAction.implementation, new NativeCallback(function(action) {
      // 创建一个新的 UIAlertAction，该动作仅关闭 UIAlertController
      const UIAlertAction = ObjC.classes.UIAlertAction;
      const handler = new ObjC.Block({
        retType: 'void',
        argTypes: ['object'],
        implementation: function() {
          // 这里是关闭 UIAlertController 的代码
          // 由于这个动作不需要执行任何操作，所以这里不写代码
        }
      });
      const title = 'Close'; // 这是新动作的标题，你可以根据需要更改
      const style = 0; // 使用默认样式
      const closeAction = UIAlertAction.actionWithTitle_style_handler_(title, style, handler);
  
      // 调用原始的 addAction: 方法，将新的动作添加到 UIAlertController 中
      const originalAddAction = new ObjC.Object(this.context.x0); // x0 寄存器通常包含 'self'
    originalAddAction['- addAction:'](closeAction);
  
    }, 'void', ['pointer', 'pointer']));
  });
  
function fuckUIActionButton(){
    var hook = eval('ObjC.classes.UIAlertController["- addAction:"]');
    Interceptor.attach(hook.implementation,{
        onEnter:function(args){
            console.log("==================== "+ " ====================");

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

          const argCount = occurrences(argSelStr, ":");
          console.log("argCount: ", argCount);

          // console.log("funcName=", funcName);
          // const argCount = occurrences(funcName, ":");
          // console.log("argCount: ", argCount);

          for (let curArgIdx = 0; curArgIdx < argCount; curArgIdx++) {
            const curArg = args[curArgIdx + 2];

            // const usePtr = false;
            const usePtr = true;
            if (usePtr) {
              // console.log("usePtr=", usePtr);
              const curArgPtr = ptr(curArg);
              console.log("---------- [" + curArgIdx + "] curArgPtr=" + curArgPtr);
              if (!curArgPtr.isNull()) {
                const curArgPtrObj = new ObjC.Object(curArgPtr);
                console.log("curArgPtrObj: ", curArgPtrObj);
                console.log("curArgPtrObj className: ", curArgPtrObj.$className);
                console.log("curArgPtrObj kind: ", curArgPtrObj.$kind);
              }
            } else {
              console.log("---------- [" + curArgIdx + "] curArg=" + curArg);
              if (curArg && (curArg != 0x0)) {
                // console.log("curArg className: ", curArg.$className);
                const curArgObj = new ObjC.Object(curArg);
                console.log("curArgObj: ", curArgObj);
                console.log("curArgObj className: ", curArgObj.$className);
                console.log("curArgObj kind: ", curArgObj.$kind);
              }
            }
          }
        }
    })
}
//patch_class_method_impl("MBTabBarController","- checkDeviceRootWarning")
//patch_class_method_impl("MBTabBarController","- viewDidAppear:")

//patch_class_method("SCInterface","+ isRoot")
//patch_class_method_impl("MBTarBarController","- setRootType:")
//patch_class_method_bool("MBTabBarController","- rootType")
//patch_class_method_bool("MBTabBarController","- rootTypeisValid:")
//hook_class_method("MBTabBarController","- rootType")
//hook_class_method("RiskStub","+ initBangcleEverisk:")
//patch_class_method_impl("Sciapodous")
//patch_class_method_impl("MsgRbKVPGCrUcJUf","- secsdk_didFinishLaunching:")
//hook_class_method("UPWRNUtil","+ isJailbroken")
//patch_class_method_impl("ShumeiSystemUtils","+ getSystemInfo:")
//patch_class_method_impl_silence("ycCmkCGvmbKLDoaS","+ toWlaXZlGDcFldxp")
hook_all_methods_of_classes_app_only()
setTimeout(function() {
    if (ObjC.available) {
        console.log("[*] Objective-C runtime is available.");

        try {
            var hook =
                ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
            console.log(
                "[*] LAContext class method evaluatePolicy:localizedReason:reply: found."
            );

            Interceptor.attach(hook.implementation, {
                onEnter: function(args) {
                    console.log("[*] Intercepting method invocation...");
                    console.log("[+] Policy: " + args[2].toString());
                    console.log(
                        "[+] Localized Reason: " + ObjC.Object(args[3]).toString()
                    );

                    var block = new ObjC.Block(args[4]);
                    console.log("[*] Original reply block obtained.");

                    const callback = block.implementation;
                    console.log("[*] Original block implementation obtained.");

                    block.implementation = function(error, value) {
                        console.log(
                            "[*] Modifying block implementation to bypass Touch ID..."
                        );
                        console.log("[+] Original error value: " + error);
                        console.log("[+] Original success value: " + value);

                        console.log("[*] Touch ID has been bypassed successfully!");
                        return callback(true, null);
                    };

                    console.log("[*] Block implementation modified successfully.");
                },
                onLeave: function(retval) {
                    console.log("[*] Leaving method invocation...");
                    console.log("[+] Return Value: " + retval.toString());
                },
            });
        } catch (error) {
            console.error("[-] Error occurred: " + error.message);
        }
    } else {
        console.error("[-] Objective-C Runtime is not available!");
    }
}, 0);
hook_specific_method_of_class("LAContext","- evaluatedPolicyDomainState");

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
patch_class_method_impl("RYTConfig","- proxyDetectionAndShowAlert");
/*
    https://kov4l3nko.github.io/blog/2018-05-27-sll-pinning-hook-sectrustevaluate/

	****************************************
	 killSSL.js Frida script
	 by Dima Kovalenko
	****************************************
	
	Usage:
		
		1. Run Viber on the device
		
		2. Inject the script to the process:
			$ frida -U -n Viber  -l path/to/killSSL.js
		
		3. SSL pinning in Viber HTTPs is
		   disabled. Now you can intercept
		   Viber HTTPs requests, e.g. with
		   mitmproxy.
*/
var DEBUG = false;

